
rule Trojan_BAT_AsyncRAT_BGK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 14 fe 01 13 06 11 06 2c 02 2b 35 07 ?? ?? 00 00 0a 0c 08 ?? ?? 00 00 0a 0d 09 ?? ?? 00 00 0a 8e 2d 03 14 2b 0f 17 8d 10 00 00 01 25 16 16 8d 24 00 00 01 a2 13 04 09 14 11 04 ?? ?? 00 00 0a 26 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AsyncRAT_BGK_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.BGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 07 16 73 32 00 00 0a 0d 73 33 00 00 0a 13 04 09 11 04 ?? ?? 00 00 0a 11 04 ?? ?? 00 00 0a 13 05 de 30 11 04 2c 07 11 04 ?? ?? 00 00 0a dc 09 2c 06 09 ?? ?? 00 00 0a dc } //2
		$a_01_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_2 = {49 73 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsRemoteDebuggerPresent
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}