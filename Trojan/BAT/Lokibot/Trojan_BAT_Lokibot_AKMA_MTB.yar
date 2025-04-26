
rule Trojan_BAT_Lokibot_AKMA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.AKMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 0a 06 19 5a 20 00 01 00 00 5d 0a 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 00 00 0a 1f 55 61 d2 9c 25 17 0f 00 28 ?? 00 00 0a 20 aa 00 00 00 61 d2 9c 25 18 0f 00 28 ?? 00 00 0a 1f 33 61 d2 9c } //3
		$a_03_1 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0b } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}