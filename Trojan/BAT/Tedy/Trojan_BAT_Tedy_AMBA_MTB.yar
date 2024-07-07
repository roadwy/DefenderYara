
rule Trojan_BAT_Tedy_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Tedy.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 09 07 16 09 6f 90 01 01 00 00 0a 17 59 6f 90 01 01 00 00 0a 17 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0c 00 11 04 17 58 13 04 11 04 02 fe 04 13 06 11 06 2d d0 90 00 } //1
		$a_80_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 67 6f 64 5c 75 70 2e 65 78 65 } //c:\windows\god\up.exe  1
		$a_80_2 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 67 6f 64 5c 73 65 6e 64 62 2e 65 78 65 } //c:\windows\god\sendb.exe  1
		$a_80_3 = {73 65 6e 64 62 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //sendb.Properties.Resources.resources  1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}