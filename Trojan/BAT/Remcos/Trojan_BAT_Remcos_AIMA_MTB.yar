
rule Trojan_BAT_Remcos_AIMA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AIMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 08 a2 25 0d 14 14 17 8d 5e 00 00 01 25 16 17 9c 25 13 04 28 ?? ?? ?? 0a 11 04 16 91 } //2
		$a_01_1 = {46 00 6c 00 79 00 50 00 75 00 73 00 68 00 42 00 6f 00 6f 00 6b 00 73 00 } //1 FlyPushBooks
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}