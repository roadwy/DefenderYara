
rule Trojan_Win32_SuspRdpConfig_ZPA{
	meta:
		description = "Trojan:Win32/SuspRdpConfig.ZPA,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {20 00 61 00 64 00 64 00 20 00 } //1  add 
		$a_00_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 54 00 65 00 72 00 6d 00 69 00 6e 00 61 00 6c 00 20 00 53 00 65 00 72 00 76 00 65 00 72 00 5c 00 57 00 69 00 6e 00 53 00 74 00 61 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 52 00 44 00 50 00 2d 00 54 00 63 00 70 00 } //1 System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
		$a_00_2 = {2f 00 76 00 20 00 50 00 6f 00 72 00 74 00 4e 00 75 00 6d 00 62 00 65 00 72 00 20 00 } //1 /v PortNumber 
		$a_00_3 = {2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 44 00 57 00 4f 00 52 00 44 00 20 00 2f 00 64 00 20 00 } //1 /t REG_DWORD /d 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}