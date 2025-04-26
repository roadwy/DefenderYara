
rule Trojan_Win64_NimzLoader_PA_MTB{
	meta:
		description = "Trojan:Win64/NimzLoader.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 61 74 61 6c 2e 6e 69 6d } //1 fatal.nim
		$a_03_1 = {31 c0 48 89 ca 49 63 0c ?? 48 89 e6 8a 0c 0a 88 0c 04 48 ff c0 48 83 f8 ?? 75 ea 48 89 d7 b9 ?? ?? ?? ?? 31 c0 f3 a5 48 83 c4 ?? 5e 5f c3 31 c0 41 39 c0 7e ?? 44 8a 0c 02 44 30 0c 01 48 ff c0 eb ?? 31 c0 c3 } //2
		$a_03_2 = {48 89 ea 31 db eb [0-04] 40 30 7c 1e ?? 48 8b 16 48 39 da 76 ?? 48 89 f8 48 c1 f8 ?? 30 44 1e ?? 48 8b 16 48 39 d3 0f 83 ?? ?? ?? ?? 48 89 f8 48 c1 f8 ?? 30 44 1e ?? 48 8b 16 48 39 da 76 ?? 48 89 f8 48 83 c7 ?? 48 c1 f8 ?? 30 44 1e ?? 48 83 c3 ?? 48 39 dd 0f 8e ?? ?? ?? ?? 48 8b 16 48 39 d3 72 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=3
 
}