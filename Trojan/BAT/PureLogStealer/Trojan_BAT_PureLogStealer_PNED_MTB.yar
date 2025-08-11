
rule Trojan_BAT_PureLogStealer_PNED_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.PNED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 17 6f ?? 00 00 0a 11 04 18 6f ?? 00 00 0a 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 73 0c 00 00 0a 13 05 11 05 11 04 6f ?? 00 00 0a 17 73 0e 00 00 0a 13 06 11 06 02 16 02 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a de 0c } //4
		$a_01_1 = {28 13 00 00 0a 7e 17 00 00 04 6f 72 00 00 0a 74 29 00 00 01 fe 09 00 00 8c 41 00 00 01 6f 4d 00 00 0a 74 18 00 00 01 2a } //2
		$a_01_2 = {06 28 05 00 00 0a 0c 07 28 05 00 00 0a 0d de 07 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=7
 
}