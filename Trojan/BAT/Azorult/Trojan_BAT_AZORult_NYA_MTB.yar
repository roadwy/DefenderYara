
rule Trojan_BAT_AZORult_NYA_MTB{
	meta:
		description = "Trojan:BAT/AZORult.NYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 ?? ?? ?? 0a 73 ?? ?? ?? 0a 0c 08 07 6f ?? ?? ?? 0a de 0a } //1
		$a_03_1 = {95 a2 29 09 0b 00 00 00 ?? ?? ?? 00 16 00 00 01 00 00 00 3a 00 00 00 09 00 00 00 06 00 00 00 18 00 00 00 07 00 00 00 37 00 00 00 18 00 00 00 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}