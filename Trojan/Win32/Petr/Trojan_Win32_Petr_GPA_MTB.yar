
rule Trojan_Win32_Petr_GPA_MTB{
	meta:
		description = "Trojan:Win32/Petr.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 8a 5c 24 08 32 da 83 f1 ea 03 0d 90 01 02 40 00 83 e1 90 01 05 40 00 33 ca 6b c1 32 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}