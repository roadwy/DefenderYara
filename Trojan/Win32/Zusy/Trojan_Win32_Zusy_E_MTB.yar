
rule Trojan_Win32_Zusy_E_MTB{
	meta:
		description = "Trojan:Win32/Zusy.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c1 88 04 14 42 0f be d2 83 fa 4d 7c e1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}