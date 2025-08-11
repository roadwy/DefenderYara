
rule Trojan_Win64_Ulise_AUL_MTB{
	meta:
		description = "Trojan:Win64/Ulise.AUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 48 63 d0 48 8b 45 e0 48 01 d0 0f b6 10 8b 45 fc 48 63 c8 48 8b 45 e0 48 01 c8 83 f2 55 88 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}