
rule Trojan_Win32_SmokeLoader_DT_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 61 70 69 6d 6f 68 69 62 6f 7a 61 79 6f 63 65 78 6f 6a 69 6b 65 79 65 66 61 20 6b 61 63 75 6a 61 77 65 6d 6f 6a 69 6d 65 6e 61 64 61 6e 65 64 6f 6d } //1 sapimohibozayocexojikeyefa kacujawemojimenadanedom
		$a_01_1 = {6c 65 77 61 79 69 76 65 73 75 72 65 6a 75 6d 65 77 } //1 lewayivesurejumew
		$a_01_2 = {48 61 6b 65 72 69 76 69 70 61 20 64 65 6a 75 72 65 70 6f 20 7a 6f 74 6f 66 75 63 75 77 6f } //1 Hakerivipa dejurepo zotofucuwo
		$a_01_3 = {6d 69 66 69 70 65 73 61 6e 61 68 65 77 6f 78 65 7a 75 73 75 77 6f 70 61 78 65 78 6f 63 } //1 mifipesanahewoxezusuwopaxexoc
		$a_01_4 = {62 65 76 65 76 65 6e 6f 77 65 77 61 6b 6f 62 61 6e 75 64 61 6d 75 72 6f } //1 bevevenowewakobanudamuro
		$a_01_5 = {63 00 65 00 78 00 6f 00 6c 00 65 00 6e 00 6f 00 72 00 75 00 7a 00 6f 00 64 00 65 00 6a 00 65 00 73 00 75 00 78 00 61 00 72 00 65 00 6e 00 69 00 63 00 20 00 70 00 6f 00 70 00 69 00 72 00 69 00 20 00 62 00 69 00 6e 00 20 00 78 00 75 00 6a 00 6f 00 67 00 69 00 68 00 75 00 6c 00 6f 00 7a 00 75 00 77 00 69 00 68 00 69 00 76 00 6f 00 66 00 69 00 7a 00 65 00 68 00 75 00 6e 00 75 00 } //1 cexolenoruzodejesuxarenic popiri bin xujogihulozuwihivofizehunu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}