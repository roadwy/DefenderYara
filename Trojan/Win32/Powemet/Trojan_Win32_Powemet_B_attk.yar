
rule Trojan_Win32_Powemet_B_attk{
	meta:
		description = "Trojan:Win32/Powemet.B!attk,SIGNATURE_TYPE_CMDHSTR_EXT,10 00 10 00 04 00 00 05 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 } //01 00  regsvr32
		$a_00_1 = {2f 00 69 00 3a 00 75 00 72 00 6c 00 3a 00 68 00 74 00 74 00 70 00 } //01 00  /i:url:http
		$a_00_2 = {2d 00 69 00 3a 00 75 00 72 00 6c 00 3a 00 68 00 74 00 74 00 70 00 } //0a 00  -i:url:http
		$a_00_3 = {20 00 73 00 63 00 72 00 6f 00 62 00 6a 00 2e 00 64 00 6c 00 6c 00 } //00 00   scrobj.dll
	condition:
		any of ($a_*)
 
}