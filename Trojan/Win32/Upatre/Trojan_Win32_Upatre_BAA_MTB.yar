
rule Trojan_Win32_Upatre_BAA_MTB{
	meta:
		description = "Trojan:Win32/Upatre.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 09 47 8b c1 59 33 d0 59 8b c2 5a 88 27 4a 8b c2 46 85 c0 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}