
rule Trojan_BAT_BitRAT_NIT_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {6f 8a 01 00 0a 0a 08 12 03 fe 90 01 04 02 12 03 16 7d 90 01 02 00 04 12 03 11 04 7d 90 01 02 00 04 09 6f 90 01 02 00 0a 90 00 } //5
		$a_01_1 = {61 64 64 5f 52 65 73 6f 75 72 63 65 52 65 73 6f 6c 76 65 } //1 add_ResourceResolve
		$a_01_2 = {42 69 74 52 41 54 2e 65 78 65 } //1 BitRAT.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}