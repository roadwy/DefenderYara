
rule Trojan_BAT_Taskun_BAA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 c9 00 00 0a 00 06 8e b7 18 da 16 da 17 d6 6b 28 cc 00 00 0a 5a 28 cd 00 00 0a 22 00 00 80 3f 58 6b 6c 28 ce 00 00 0a b7 13 04 08 06 11 04 93 6f cf 00 00 0a 26 00 09 17 d6 0d 09 11 05 13 06 11 06 31 bc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}