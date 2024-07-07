
rule Trojan_Win64_NimLoader_RCB_MTB{
	meta:
		description = "Trojan:Win64/NimLoader.RCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_00_0 = {49 6e 76 61 6c 69 64 20 68 65 78 20 63 68 61 72 } //1 Invalid hex char
		$a_01_1 = {48 8b 54 24 48 48 89 83 68 20 00 00 48 81 83 70 20 00 00 00 10 00 00 48 89 70 10 48 c7 00 e8 0f 00 00 48 c7 40 08 18 00 00 00 48 8b 8b 68 20 00 00 4c 8b 41 08 48 29 11 4e 8d 0c 01 49 01 d0 4c 89 41 08 4c 89 c9 } //5
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*5) >=6
 
}