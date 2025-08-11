
rule Trojan_BAT_DarkTortilla_MSZ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MSZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 09 0b 04 03 07 5d 9a 28 ?? 01 00 0a 02 28 ?? 00 00 06 28 ?? 01 00 0a 0a 2b 00 06 2a } //5
		$a_01_1 = {02 03 66 5f 02 66 03 5f 60 8c 66 00 00 01 0a 2b 00 06 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}