
rule Trojan_BAT_RemcosRAT_NT_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 09 07 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06 de 07 } //1
		$a_01_1 = {1f a2 0b 09 07 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 8d 00 00 00 95 00 00 00 6d 03 00 00 92 07 00 00 4d 05 00 00 13 } //1
		$a_01_2 = {53 6d 61 6c 6c 65 73 74 45 6e 63 6c 6f 73 69 6e 67 43 69 72 63 6c 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 SmallestEnclosingCircle.Properties.Resources
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}