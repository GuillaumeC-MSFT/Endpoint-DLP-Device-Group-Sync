<#
================================================================================
Sync-UserGroupDevicesToDeviceGroup.ps1
================================================================================

PURPOSE
    PowerShell utility that identifies Microsoft Entra registered devices
    associated with users in a source security group and synchronizes those
    devices into a destination device security group.

    The script supports interactive execution scenarios, multiple authentication
    methods, validation checks, reporting, logging, retry handling, and Microsoft
    Graph operations.

    Common use cases include:
      - Building a device security group from a user security group.
      - Validating user-to-device relationships in Microsoft Entra ID.
      - Identifying users without associated registered devices.
      - Preparing or validating device-scoped deployments, including Endpoint DLP.

IMPORTANT ENDPOINT DLP NOTE
    This script is user-first. It starts with users and asks Microsoft Graph which
    devices are associated with each user. Kiosk, shared, or userless devices are
    not expected to be matched because there is no user-to-device relationship to use.

    Users in the source group with no associated device are highlighted clearly
    because they may not be represented in device-scoped policies that depend on
    both user and device group matching.

DISCLAIMER
    This script is provided as a sample and starting point only. It should be
    reviewed, validated, and tested in a non-production environment before using
    it in production.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

REQUIREMENTS
    - Windows PowerShell 5.1 or PowerShell 7+
    - Microsoft Graph PowerShell SDK
    - Microsoft Entra permissions to read users/devices/groups and update group membership

    If Microsoft Graph PowerShell is missing, the script can offer to install:
        Install-Module
