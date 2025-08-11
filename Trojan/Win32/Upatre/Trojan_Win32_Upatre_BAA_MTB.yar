
rule Trojan_Win32_Upatre_BAA_MTB{
	meta:
		description = "Trojan:Win32/Upatre.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 db 8a 06 c6 04 1f ff 20 04 1f 46 47 49 eb eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Upatre_BAA_MTB_2{
	meta:
		description = "Trojan:Win32/Upatre.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 09 47 8b c1 59 33 d0 59 8b c2 5a 88 27 4a 8b c2 46 85 c0 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}