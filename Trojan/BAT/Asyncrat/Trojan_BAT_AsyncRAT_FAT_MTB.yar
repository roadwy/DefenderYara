
rule Trojan_BAT_AsyncRAT_FAT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.FAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 06 02 7d ?? 00 00 04 06 03 7d ?? 00 00 04 17 80 ?? 00 00 04 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 73 ?? 00 00 0a 25 16 6f ?? 00 00 0a 6f ?? 00 00 0a de 03 26 de } //3
		$a_01_1 = {58 00 6a 00 70 00 63 00 6c 00 69 00 65 00 6e 00 74 00 73 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 31 00 } //1 Xjpclientser.Resource1
		$a_01_2 = {75 00 6e 00 73 00 64 00 6b 00 2e 00 62 00 61 00 74 00 } //1 unsdk.bat
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}