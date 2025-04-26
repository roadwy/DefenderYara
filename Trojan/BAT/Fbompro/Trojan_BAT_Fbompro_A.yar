
rule Trojan_BAT_Fbompro_A{
	meta:
		description = "Trojan:BAT/Fbompro.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 02 7b 13 00 00 04 72 ?? ?? 00 70 28 66 00 00 0a 28 9e 00 00 0a 2c 1a 02 7b 13 00 00 04 72 ?? ?? 00 70 28 66 00 00 0a 28 9e 00 00 0a 16 fe 01 } //1
		$a_01_1 = {17 8d 86 00 00 01 13 0e 11 0e 16 1f 7c 9d 11 0e 6f c9 00 00 0a 0a 06 8e 69 19 fe 01 16 fe 01 13 0d 11 0d 3a 42 } //1
		$a_00_2 = {77 63 5f 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 43 6f 6d 70 6c 65 74 65 64 } //1 wc_DownloadFileCompleted
		$a_00_3 = {4b 69 6c 6c 46 42 50 72 6f 6d 6f } //1 KillFBPromo
		$a_00_4 = {66 00 66 00 72 00 75 00 6e 00 } //1 ffrun
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}