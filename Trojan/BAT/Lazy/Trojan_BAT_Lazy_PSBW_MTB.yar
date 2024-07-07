
rule Trojan_BAT_Lazy_PSBW_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 00 72 3d 08 00 70 28 41 90 01 03 0a 06 6f 42 90 01 03 0b 07 6f 43 90 01 03 0c 73 44 90 01 03 0d 08 09 28 15 00 00 06 00 09 6f 45 90 01 03 80 5e 00 00 04 28 17 00 00 06 00 7e 5e 00 00 04 13 04 2b 00 11 04 2a 90 00 } //5
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}