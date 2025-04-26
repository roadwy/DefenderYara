
rule Trojan_BAT_Jalapeno_AJ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 7d 92 01 00 04 16 0a 02 7b 93 01 00 04 16 12 00 28 46 02 00 0a 06 2c 0e 04 02 7b 92 01 00 04 } //2
		$a_80_1 = {55 6d 62 72 61 6c 20 53 74 65 61 6c 65 72 } //Umbral Stealer  2
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}