
rule Trojan_Win32_Sefnit_AN{
	meta:
		description = "Trojan:Win32/Sefnit.AN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 25 64 2d 25 64 2d 25 64 5f 47 54 43 5f 54 4d 50 5f } //01 00  /%d-%d-%d_GTC_TMP_
		$a_01_1 = {77 72 6d 5f 6d 75 74 65 78 } //01 00  wrm_mutex
		$a_01_2 = {73 65 6c 66 2d 6d 75 72 64 65 72 } //00 00  self-murder
	condition:
		any of ($a_*)
 
}