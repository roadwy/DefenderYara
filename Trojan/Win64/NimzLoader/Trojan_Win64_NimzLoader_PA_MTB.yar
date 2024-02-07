
rule Trojan_Win64_NimzLoader_PA_MTB{
	meta:
		description = "Trojan:Win64/NimzLoader.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 61 74 61 6c 2e 6e 69 6d } //02 00  fatal.nim
		$a_03_1 = {31 c0 48 89 ca 49 63 0c 90 01 01 48 89 e6 8a 0c 0a 88 0c 04 48 ff c0 48 83 f8 90 01 01 75 ea 48 89 d7 b9 90 01 04 31 c0 f3 a5 48 83 c4 90 01 01 5e 5f c3 31 c0 41 39 c0 7e 90 01 01 44 8a 0c 02 44 30 0c 01 48 ff c0 eb 90 01 01 31 c0 c3 90 00 } //02 00 
		$a_03_2 = {48 89 ea 31 db eb 90 02 04 40 30 7c 1e 90 01 01 48 8b 16 48 39 da 76 90 01 01 48 89 f8 48 c1 f8 90 01 01 30 44 1e 90 01 01 48 8b 16 48 39 d3 0f 83 90 01 04 48 89 f8 48 c1 f8 90 01 01 30 44 1e 90 01 01 48 8b 16 48 39 da 76 90 01 01 48 89 f8 48 83 c7 90 01 01 48 c1 f8 90 01 01 30 44 1e 90 01 01 48 83 c3 90 01 01 48 39 dd 0f 8e 90 01 04 48 8b 16 48 39 d3 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}