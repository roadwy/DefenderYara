
rule Trojan_Win32_Guloader_GTZ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {62 72 75 69 73 65 64 5c 63 61 6c 79 70 73 6f 65 72 6e 65 5c 64 72 69 6b 6b 65 6c 61 67 65 74 } //1 bruised\calypsoerne\drikkelaget
		$a_01_1 = {70 61 74 72 69 6f 74 69 73 6d 65 6e 5c 41 69 72 65 2e 69 6e 69 } //1 patriotismen\Aire.ini
		$a_01_2 = {6a 65 6e 6b 72 6f 67 73 5c 73 74 61 74 73 73 6b 61 74 74 65 72 6e 65 2e 69 6e 69 } //1 jenkrogs\statsskatterne.ini
		$a_01_3 = {74 72 61 70 70 65 72 5c 67 65 6e 6e 65 6d 74 72 61 77 6c 2e 69 6e 69 } //1 trapper\gennemtrawl.ini
		$a_80_4 = {62 72 6e 65 66 64 73 65 6c 73 64 61 67 65 6e } //brnefdselsdagen  1
		$a_01_5 = {65 72 66 61 72 69 6e 67 65 72 5c 6b 61 6c 76 65 6b 72 73 65 6e 65 2e 73 61 62 } //1 erfaringer\kalvekrsene.sab
		$a_01_6 = {54 69 6c 6c 69 64 73 68 76 65 72 76 73 } //1 Tillidshvervs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}