
rule Backdoor_BAT_DarkCrypt_MTB{
	meta:
		description = "Backdoor:BAT/DarkCrypt!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {62 64 2e 64 61 72 6b 6b 6b 69 73 2e 63 6f 6d } //bd.darkkkis.com  01 00 
		$a_80_1 = {43 6f 6e 74 72 6f 6c 5c 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 5c 57 69 6e 53 74 61 74 69 6f 6e 73 5c 52 44 50 2d 54 63 70 } //Control\Terminal Server\WinStations\RDP-Tcp  01 00 
		$a_80_2 = {64 68 63 70 2e 65 78 65 } //dhcp.exe  01 00 
		$a_80_3 = {64 68 63 70 2e 49 6e 73 74 61 6c 6c 4c 6f 67 } //dhcp.InstallLog  01 00 
		$a_00_4 = {73 65 74 5f 55 73 65 72 43 61 6e 6e 6f 74 43 68 61 6e 67 65 50 61 73 73 77 6f 72 64 } //00 00  set_UserCannotChangePassword
	condition:
		any of ($a_*)
 
}