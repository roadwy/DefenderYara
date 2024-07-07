
rule Trojan_Win32_Agent_EU{
	meta:
		description = "Trojan:Win32/Agent.EU,SIGNATURE_TYPE_PEHSTR_EXT,18 00 17 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 63 00 6f 00 6e 00 69 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } //10
		$a_01_2 = {48 4e 65 74 43 66 67 2e 46 77 4d 67 72 } //1 HNetCfg.FwMgr
		$a_01_3 = {48 4e 65 74 43 66 67 2e 46 77 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e } //1 HNetCfg.FwAuthorizedApplication
		$a_01_4 = {72 65 63 76 66 72 6f 6d } //1 recvfrom
		$a_01_5 = {63 6d 64 3d 63 6c 69 63 6b 30 6f 6b } //1 cmd=click0ok
		$a_01_6 = {63 6d 64 3d 65 78 65 63 6f 6b } //1 cmd=execok
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=23
 
}