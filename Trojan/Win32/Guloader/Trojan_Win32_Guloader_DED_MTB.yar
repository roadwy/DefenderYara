
rule Trojan_Win32_Guloader_DED_MTB{
	meta:
		description = "Trojan:Win32/Guloader.DED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 00 4f 00 78 00 64 00 53 00 63 00 58 00 6e 00 67 00 45 00 34 00 30 00 4a 00 6d 00 4b 00 4b 00 72 00 4c 00 6b 00 55 00 76 00 63 00 6a 00 6b 00 72 00 30 00 67 00 7a 00 46 00 4b 00 34 00 33 00 } //1 nOxdScXngE40JmKKrLkUvcjkr0gzFK43
		$a_01_1 = {6c 00 61 00 6e 00 64 00 62 00 72 00 75 00 67 00 73 00 64 00 72 00 69 00 66 00 74 00 73 00 62 00 79 00 67 00 6e 00 69 00 6e 00 67 00 65 00 6e 00 } //1 landbrugsdriftsbygningen
		$a_01_2 = {4b 00 36 00 4a 00 47 00 77 00 6a 00 49 00 38 00 65 00 68 00 4f 00 33 00 36 00 36 00 6c 00 4c 00 39 00 77 00 79 00 58 00 75 00 34 00 74 00 37 00 37 00 } //1 K6JGwjI8ehO366lL9wyXu4t77
		$a_01_3 = {77 00 41 00 33 00 42 00 69 00 48 00 47 00 32 00 6b 00 53 00 43 00 39 00 70 00 78 00 33 00 4a 00 69 00 68 00 54 00 6c 00 69 00 59 00 59 00 4e 00 34 00 38 00 38 00 } //1 wA3BiHG2kSC9px3JihTliYYN488
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}