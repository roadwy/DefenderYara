
rule Trojan_BAT_LummaC_EZ_MTB{
	meta:
		description = "Trojan:BAT/LummaC.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {33 37 35 63 35 65 66 66 2d 30 36 35 30 2d 34 33 30 31 2d 38 35 65 66 2d 33 38 32 63 66 65 66 61 39 61 64 66 } //2 375c5eff-0650-4301-85ef-382cfefa9adf
		$a_81_1 = {63 3a 5c 35 36 7a 6d 5c 78 7a 64 39 5c 6f 62 6a 5c 52 65 6c 65 61 73 5c 5a 61 71 31 2e 70 64 62 70 64 62 } //2 c:\56zm\xzd9\obj\Releas\Zaq1.pdbpdb
		$a_81_2 = {43 61 6c 6c 57 69 6e 64 6f 77 50 72 6f 63 41 } //1 CallWindowProcA
		$a_81_3 = {50 65 77 74 65 72 65 72 20 48 65 61 72 73 65 73 20 49 6e 74 65 72 73 65 73 73 69 6f 6e } //1 Pewterer Hearses Intersession
		$a_81_4 = {42 61 72 67 65 6c 6c 6f 20 45 6e 63 69 72 63 6c 65 6d 65 6e 74 73 } //1 Bargello Encirclements
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}