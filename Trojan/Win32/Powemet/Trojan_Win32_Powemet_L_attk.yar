
rule Trojan_Win32_Powemet_L_attk{
	meta:
		description = "Trojan:Win32/Powemet.L!attk,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 } //0a 00  regsvr32
		$a_00_1 = {73 00 63 00 72 00 6f 00 62 00 6a 00 2e 00 64 00 6c 00 6c 00 } //0a 00  scrobj.dll
		$a_00_2 = {2e 00 73 00 63 00 74 00 } //01 00  .sct
		$a_00_3 = {20 00 2f 00 69 00 3a 00 } //01 00   /i:
		$a_00_4 = {20 00 2d 00 69 00 3a 00 } //00 00   -i:
	condition:
		any of ($a_*)
 
}