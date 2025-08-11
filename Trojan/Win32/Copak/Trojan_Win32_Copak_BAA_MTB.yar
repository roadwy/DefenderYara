
rule Trojan_Win32_Copak_BAA_MTB{
	meta:
		description = "Trojan:Win32/Copak.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 3a 29 c1 81 c2 04 00 00 00 01 c9 46 39 da 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}