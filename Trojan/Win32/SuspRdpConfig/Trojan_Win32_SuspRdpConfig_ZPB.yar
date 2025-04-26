
rule Trojan_Win32_SuspRdpConfig_ZPB{
	meta:
		description = "Trojan:Win32/SuspRdpConfig.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6e 00 65 00 74 00 73 00 68 00 } //1 netsh
		$a_00_1 = {61 00 64 00 76 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 72 00 75 00 6c 00 65 00 20 00 6e 00 61 00 6d 00 65 00 3d 00 } //1 advfirewall firewall add rule name=
		$a_00_2 = {52 00 44 00 50 00 50 00 4f 00 52 00 54 00 4c 00 61 00 74 00 65 00 73 00 74 00 2d 00 54 00 43 00 50 00 2d 00 49 00 6e 00 } //1 RDPPORTLatest-TCP-In
		$a_00_3 = {64 00 69 00 72 00 3d 00 69 00 6e 00 20 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 61 00 6c 00 6c 00 6f 00 77 00 20 00 70 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 3d 00 54 00 43 00 50 00 20 00 6c 00 6f 00 63 00 61 00 6c 00 70 00 6f 00 72 00 74 00 3d 00 } //1 dir=in action=allow protocol=TCP localport=
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule Trojan_Win32_SuspRdpConfig_ZPB_2{
	meta:
		description = "Trojan:Win32/SuspRdpConfig.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {20 00 61 00 64 00 64 00 20 00 } //1  add 
		$a_00_1 = {5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 54 00 65 00 72 00 6d 00 69 00 6e 00 61 00 6c 00 20 00 53 00 65 00 72 00 76 00 65 00 72 00 5c 00 57 00 69 00 6e 00 53 00 74 00 61 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 52 00 44 00 50 00 2d 00 54 00 63 00 70 00 } //1 \SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
		$a_00_2 = {2f 00 76 00 20 00 55 00 73 00 65 00 72 00 41 00 75 00 74 00 68 00 65 00 6e 00 74 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 2f 00 64 00 20 00 30 00 20 00 } //1 /v UserAuthentication /d 0 
		$a_00_3 = {2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 44 00 57 00 4f 00 52 00 44 00 } //1 /t REG_DWORD
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}