
rule Ransom_Win32_BastaLoader_SA{
	meta:
		description = "Ransom:Win32/BastaLoader.SA,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 } //1 rundll32
		$a_00_1 = {2e 00 64 00 6c 00 6c 00 2c 00 76 00 69 00 73 00 69 00 62 00 6c 00 65 00 65 00 6e 00 74 00 72 00 79 00 } //10 .dll,visibleentry
		$a_00_2 = {64 00 61 00 76 00 73 00 65 00 74 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 } //-100 davsetcookie
		$a_00_3 = {68 00 67 00 73 00 70 00 6f 00 72 00 74 00 61 00 6c 00 73 00 65 00 74 00 75 00 70 00 78 00 38 00 36 00 5f 00 63 00 } //-100 hgsportalsetupx86_c
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*10+(#a_00_2  & 1)*-100+(#a_00_3  & 1)*-100) >=11
 
}