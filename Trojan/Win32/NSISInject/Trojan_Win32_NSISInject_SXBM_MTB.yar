
rule Trojan_Win32_NSISInject_SXBM_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.SXBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_81_0 = {65 70 69 6c 65 70 74 6f 69 64 5c 43 68 61 72 6d 65 74 72 6f 6c 64 65 6e } //2 epileptoid\Charmetrolden
		$a_81_1 = {62 69 6e 74 6a 65 6b 61 72 74 6f 66 66 65 6c 65 6e 2e 61 76 6f } //1 bintjekartoffelen.avo
		$a_81_2 = {4c 75 6b 6b 65 74 69 64 65 72 73 32 32 37 5c 73 69 6f 75 78 65 6e 73 } //1 Lukketiders227\siouxens
		$a_81_3 = {44 65 6e 6f 74 61 74 75 6d 2e 69 6e 69 } //1 Denotatum.ini
		$a_81_4 = {47 6c 79 70 74 6f 67 72 61 70 68 2e 74 78 74 } //1 Glyptograph.txt
		$a_81_5 = {53 75 62 73 69 73 74 65 6e 73 6c 73 65 2e 69 6e 69 } //1 Subsistenslse.ini
		$a_81_6 = {41 66 64 65 6c 69 6e 67 73 73 79 67 65 70 6c 65 6a 65 72 73 6b 65 2e 48 75 72 31 39 37 } //1 Afdelingssygeplejerske.Hur197
		$a_81_7 = {70 72 6f 63 61 74 61 6c 65 63 74 69 63 2e 6d 69 73 } //1 procatalectic.mis
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=9
 
}