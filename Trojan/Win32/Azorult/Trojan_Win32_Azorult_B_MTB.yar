
rule Trojan_Win32_Azorult_B_MTB{
	meta:
		description = "Trojan:Win32/Azorult.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {03 d0 23 ca 0f b7 95 90 01 04 33 d1 66 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}