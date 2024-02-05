
rule Trojan_Win32_Fareit_CV_MTB{
	meta:
		description = "Trojan:Win32/Fareit.CV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 4c 70 42 00 0c 71 42 00 5c 11 40 00 6c 72 42 00 62 11 40 00 d4 38 40 00 } //00 00 
	condition:
		any of ($a_*)
 
}