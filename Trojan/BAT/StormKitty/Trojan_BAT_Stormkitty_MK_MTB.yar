
rule Trojan_BAT_Stormkitty_MK_MTB{
	meta:
		description = "Trojan:BAT/Stormkitty.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 16 6f 46 00 00 0a 25 17 6f 47 00 00 0a 25 17 6f 48 00 00 0a 25 17 6f 49 00 00 0a 25 17 6f 4a 00 00 0a 25 1f 25 28 4b 00 00 0a } //25
		$a_01_1 = {06 16 07 17 06 8e 69 28 22 00 00 0a 28 03 00 00 06 07 28 0c 00 00 06 1f 0a 28 3f 00 00 0a 18 72 39 00 00 70 28 0d 00 00 06 } //15
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*15) >=40
 
}