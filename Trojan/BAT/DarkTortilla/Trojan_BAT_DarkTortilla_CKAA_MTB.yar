
rule Trojan_BAT_DarkTortilla_CKAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.CKAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 14 72 41 0c 00 70 18 8d ?? 00 00 01 25 16 09 25 13 05 14 72 33 0c 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a a2 25 17 09 25 13 06 14 72 3b 0c 00 70 16 8d ?? 00 00 01 14 14 14 } //3
		$a_01_1 = {4c 00 20 00 6f 00 20 00 61 00 20 00 64 00 } //2 L o a d
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}