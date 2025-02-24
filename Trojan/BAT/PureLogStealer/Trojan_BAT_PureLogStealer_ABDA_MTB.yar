
rule Trojan_BAT_PureLogStealer_ABDA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ABDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {29 00 00 0a 0a 02 28 ?? 00 00 2b 6f ?? 00 00 0a 0b 38 0e 00 00 00 07 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 2d ea dd 0d 00 00 00 07 39 06 00 00 00 07 6f ?? 00 00 0a dc 06 6f ?? 00 00 0a 2a } //3
		$a_01_1 = {47 00 65 00 74 00 45 00 78 00 70 00 20 00 6f 00 72 00 74 00 65 00 64 00 54 00 20 00 79 00 70 00 65 00 73 00 } //2 GetExp ortedT ypes
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}