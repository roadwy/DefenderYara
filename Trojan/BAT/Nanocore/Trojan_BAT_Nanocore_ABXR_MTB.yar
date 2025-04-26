
rule Trojan_BAT_Nanocore_ABXR_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 38 ?? 00 00 00 00 07 09 18 7e ?? 02 00 04 28 ?? 01 00 06 1f 10 7e ?? 02 00 04 28 ?? 01 00 06 7e ?? 02 00 04 28 ?? 01 00 06 16 91 13 05 08 17 8d ?? 00 00 01 25 16 11 05 9c 6f ?? 00 00 0a 00 09 18 58 0d 00 09 07 7e ?? 02 00 04 28 ?? 01 00 06 fe 04 13 06 11 06 } //3
		$a_01_1 = {34 00 44 00 35 00 41 00 39 00 30 00 } //1 4D5A90
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}