
rule Trojan_Win32_GuLoader_SIBV1_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBV1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {45 00 70 00 69 00 6e 00 20 00 45 00 69 00 44 00 49 00 61 00 20 00 69 00 6c 00 61 00 } //1 Epin EiDIa ila
		$a_00_1 = {41 00 52 00 69 00 43 00 6c 00 65 00 20 00 41 00 46 00 52 00 70 00 6f 00 72 00 61 00 54 00 6f 00 6f 00 6e 00 } //1 ARiCle AFRporaToon
		$a_03_2 = {83 c6 01 66 90 02 0a ff 37 90 02 0a 31 34 24 90 02 0a 5b 90 02 0a 3b 5c 24 90 01 01 75 90 01 01 90 02 0a bb 90 01 04 90 18 90 02 0a 83 eb 04 90 02 0a ff 34 1f 90 02 0a 5a 90 02 0a e8 90 01 04 90 02 0a 09 14 18 90 02 0a 75 90 01 01 90 02 0a ff e0 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}