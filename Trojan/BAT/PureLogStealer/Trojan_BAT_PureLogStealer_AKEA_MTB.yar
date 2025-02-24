
rule Trojan_BAT_PureLogStealer_AKEA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AKEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 19 8d d9 00 00 01 25 16 12 00 28 ?? 00 00 0a 9c 25 17 12 00 28 ?? 00 00 0a 9c 25 18 12 00 28 ?? 00 00 0a 9c 07 28 ?? 00 00 2b 6f ?? 00 00 0a 11 05 } //3
		$a_01_1 = {03 09 1f 10 63 20 ff 00 00 00 5f d2 6f 8f 00 00 0a } //2
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}