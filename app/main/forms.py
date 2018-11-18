from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, RadioField
from wtforms.validators import Email, Length, DataRequired, Regexp, EqualTo
from wtforms import ValidationError
from ..models import Network, WirelessNetwork
from wtforms.widgets import PasswordInput
import socket
import re


class AddNetworkForm(FlaskForm):
    is_edit = False

    name = StringField('Name', render_kw={"placeholder": "network_name"}, validators=[
        DataRequired(), Length(1, 64),
        Regexp('^[A-Za-z0-9_-]+$', 0,
               'Networks must have only letters, numbers or '
               'underscores')])
    purpose = RadioField('Purpose', choices=[('Corporate', 'Corporate'), ('Guest', 'Guest')], default='Corporate')
    vlan = StringField('VLAN', render_kw={"placeholder": "2-4096"}, validators=[DataRequired()])
    # TODO: Add validation, must be e.g. 10.0.0.1/24
    network = StringField('Network', render_kw={"placeholder": "e.g. 10.0.50.0/24"}, validators=[DataRequired()])
    gateway = StringField('Gateway', render_kw={"placeholder": "e.g. 10.0.50.1"}, validators=[DataRequired()])
    dhcp_mode = RadioField('DHCP Mode', choices=[('1', 'DHCP Server'), ('0', 'None')], default='1')
    # TODO: Add DHCP Range
    # TODO: Validate lease time ?
    dhcp_lease_time = StringField('DHCP Lease Time', validators=[DataRequired()], default=86400)

    submit = SubmitField('Save')

    def validate_vlan(self, field):
        vlan_id = int(field.data)
        if vlan_id < 2 or vlan_id > 4096:
            raise ValidationError('VLAN must be a number between 2 and 4096')
        if not self.is_edit and Network.query.filter_by(vlan=vlan_id).first():
            raise ValidationError('VLAN ' + str(vlan_id) + ' is already in use')
        return True

    def validate_name(self, field):
        if not self.is_edit and Network.query.filter_by(name=field.data).first():
            raise ValidationError('Network name is already in use')

    def validate_network(self, field):
        if not self.is_edit and Network.query.filter_by(network_addr=field.data).first():
            raise ValidationError('Network subnet is already in use')
        toks = field.data.split("/")
        if len(toks) != 2:
            raise ValidationError('Invalid format')
        try:
            netmask = int(toks[1])
            if netmask < 0 or netmask > 32:
                raise ValidationError('Invalid netmask')
        except ValueError:
            raise ValidationError('Invalid netmask')

        try:
            socket.inet_aton(toks[0])
        except socket.error:
            raise ValidationError('Invalid network address')

    def validate_gateway(self, field):
        try:
            socket.inet_aton(field.data)
        except socket.error:
            raise ValidationError('Invalid gateway address')


class AddWirelessForm(FlaskForm):
    is_edit = False

    ssid = StringField('SSID', render_kw={"placeholder": "wifi network name"}, validators=[
        DataRequired(), Length(1, 64),
        Regexp('^[A-Za-z0-9_-]+$', 0,
               'SSIDs must have only letters, numbers or '
               'underscores')])
    enabled = BooleanField('Enabled', default=True)
    security = RadioField('Security', choices=[('Open', 'Open'), ('WPA Personal', 'WPA Personal')],
                         default='Open')
    #widget=PasswordInput(hide_value=False)
    password = StringField('Password')
    is_vlan = BooleanField('Use VLAN', default=True)
    vlan = StringField('VLAN', render_kw={"placeholder": "2-4096"})

    submit = SubmitField('Save')

    def validate_password(self, field):
        print(self.security.data)
        if self.security.data != 'WPA Personal':
            print('true')
            return True
        if len(self.password.data) < 8 or len(self.password.data) > 64:
            raise ValidationError('Password has to contain 8 - 64 characters')
        if not re.match(r'[A-Za-z0-9]{8,}', field.data):
            raise ValidationError('Password can contain only letters and numbers')
        return True

    def validate_vlan(self, field):
        if self.is_vlan.data is False:
            return True
        vlan_id = int(field.data)
        if vlan_id < 2 or vlan_id > 4096:
            raise ValidationError('VLAN must be a number between 2 and 4096')
        if not self.is_edit and Network.query.filter_by(vlan=vlan_id).first():
            raise ValidationError('VLAN ' + str(vlan_id) + ' is already in use')
        return True

    def validate_ssid(self, field):
        if not self.is_edit and WirelessNetwork.query.filter_by(ssid=field.data).first():
            raise ValidationError('Specified SSID is already in use')
        return True