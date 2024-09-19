
rule Trojan_Win32_MreAgent_B{
	meta:
		description = "Trojan:Win32/MreAgent.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 00 6d 00 69 00 63 00 } //1 wmic
		$a_00_1 = {70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 63 00 61 00 6c 00 6c 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 } //1 process call create
		$a_00_2 = {69 00 65 00 34 00 75 00 69 00 6e 00 69 00 74 00 2e 00 65 00 78 00 65 00 20 00 2d 00 62 00 61 00 73 00 65 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 } //1 ie4uinit.exe -basesettings
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}