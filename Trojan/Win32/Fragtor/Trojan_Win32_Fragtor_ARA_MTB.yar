
rule Trojan_Win32_Fragtor_ARA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 14 08 80 ea 7a 80 f2 19 88 14 08 40 3b c6 7c ef } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Fragtor_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 1a 99 59 f7 f9 83 c2 41 66 89 54 7d d4 47 83 ff 0a 7c e7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}