
rule Trojan_BAT_PureLogStealer_APU_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.APU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 00 02 06 16 06 8e 69 6f ?? 00 00 0a 0b 07 16 31 12 28 ?? 00 00 0a 06 16 07 6f ?? 00 00 0a 28 } //2
		$a_01_1 = {31 00 39 00 33 00 2e 00 35 00 38 00 2e 00 31 00 32 00 31 00 2e 00 32 00 35 00 30 00 } //3 193.58.121.250
		$a_01_2 = {43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00 20 00 74 00 6f 00 20 00 73 00 65 00 72 00 76 00 65 00 72 00 } //1 Connected to server
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=6
 
}