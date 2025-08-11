
rule Trojan_Win64_Midie_NS_MTB{
	meta:
		description = "Trojan:Win64/Midie.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {4d 29 fe 4c 39 f7 4d 89 f0 4c 0f 42 c7 48 89 d9 31 d2 e8 a4 fe ff ff 42 8d 0c fd 00 00 00 00 48 d3 e0 48 0b 46 ?? 48 89 46 ?? 49 39 fe } //2
		$a_03_1 = {48 89 f1 e8 2e ff ff ff 48 8b 46 ?? 48 31 06 48 83 66 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}