
rule Trojan_Win32_Tofsee_BAA_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 84 24 18 05 00 00 83 ac 24 18 05 00 00 7b 8b 84 24 18 05 00 00 8a 04 08 88 04 0a } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}