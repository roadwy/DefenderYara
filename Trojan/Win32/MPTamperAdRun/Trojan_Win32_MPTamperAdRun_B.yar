
rule Trojan_Win32_MPTamperAdRun_B{
	meta:
		description = "Trojan:Win32/MPTamperAdRun.B,SIGNATURE_TYPE_CMDHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 72 00 75 00 6e 00 } //10 advancedrun
		$a_00_1 = {73 00 74 00 6f 00 70 00 20 00 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00 } //10 stop windefend
		$a_00_2 = {63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 6c 00 69 00 6e 00 65 00 } //1 commandline
		$a_00_3 = {72 00 75 00 6e 00 61 00 73 00 } //1 runas
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=22
 
}