
rule Trojan_BAT_Lazy_PGL_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 1f 14 6f ?? 00 00 0a 13 04 2b 29 11 04 1f 0a fe 02 13 06 11 06 2c 0c 07 08 66 5f 07 66 08 5f 60 0d 2b 16 11 05 74 ?? 00 00 01 17 1f 14 6f ?? 00 00 0a 13 04 17 13 07 2b d2 09 28 ?? 00 00 0a 0a 06 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_BAT_Lazy_PGL_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 00 65 00 6d 00 70 00 00 13 5c 00 78 00 4c 00 6f 00 6b 00 2e 00 65 00 78 00 65 } //1
		$a_80_1 = {72 67 73 74 6a 72 65 70 72 65 73 65 6e 74 61 74 69 76 65 64 } //rgstjrepresentatived  2
		$a_80_2 = {68 76 79 64 7a 73 70 65 63 69 66 69 63 61 74 69 6f 6e 73 70 } //hvydzspecificationsp  2
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //5 DownloadFile
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_01_3  & 1)*5) >=10
 
}