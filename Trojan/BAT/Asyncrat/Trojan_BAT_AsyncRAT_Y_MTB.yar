
rule Trojan_BAT_AsyncRAT_Y_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 08 91 07 08 07 28 90 01 01 00 00 06 25 26 69 5d 91 61 d2 9c 08 1a 28 90 01 01 00 00 06 58 0c 90 00 } //2
		$a_01_1 = {52 65 73 6f 75 72 63 65 52 65 61 64 65 72 } //1 ResourceReader
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}