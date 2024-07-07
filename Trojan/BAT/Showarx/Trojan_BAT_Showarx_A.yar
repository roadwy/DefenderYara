
rule Trojan_BAT_Showarx_A{
	meta:
		description = "Trojan:BAT/Showarx.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 67 6f 6f 64 77 65 62 73 68 6f 77 2e 63 6f 6d 2f 72 65 64 69 72 65 63 74 2f 35 37 61 37 36 34 64 30 34 32 62 66 38 } //://goodwebshow.com/redirect/57a764d042bf8  8
		$a_80_1 = {41 64 73 53 68 6f 77 2e 65 78 65 } //AdsShow.exe  3
		$a_00_2 = {5c 50 72 6f 6a 65 63 74 73 5c 41 64 73 53 68 6f 77 5c } //2 \Projects\AdsShow\
		$a_00_3 = {5c 41 64 73 53 68 6f 77 5c 6f 62 6a 5c } //2 \AdsShow\obj\
		$a_00_4 = {5c 41 64 73 53 68 6f 77 2e 70 64 62 } //2 \AdsShow.pdb
		$a_00_5 = {53 6c 65 65 70 00 41 64 64 54 6f 53 74 61 72 74 75 70 00 43 75 72 72 65 6e 74 55 73 65 72 } //1 汓敥p摁呤卯慴瑲灵䌀牵敲瑮獕牥
		$a_00_6 = {5c 73 61 6d 69 5c 44 6f 63 75 6d 65 6e 74 73 5c } //1 \sami\Documents\
	condition:
		((#a_80_0  & 1)*8+(#a_80_1  & 1)*3+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=8
 
}