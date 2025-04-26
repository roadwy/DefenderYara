
rule TrojanDownloader_BAT_Perseus_GG_MTB{
	meta:
		description = "TrojanDownloader:BAT/Perseus.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 "
		
	strings :
		$a_80_0 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c } //\Google\Chrome\  10
		$a_80_1 = {64 61 74 61 2e 74 78 74 } //data.txt  10
		$a_80_2 = {73 76 73 68 6f 73 74 2e 65 78 65 } //svshost.exe  10
		$a_80_3 = {73 75 63 63 65 73 73 } //success  10
		$a_80_4 = {5c 56 65 72 69 66 6f 6e 65 20 44 61 74 61 20 56 69 65 77 65 72 5c } //\Verifone Data Viewer\  1
		$a_80_5 = {50 61 73 73 77 6f 72 64 20 69 6e 63 6f 72 72 65 63 74 21 21 21 } //Password incorrect!!!  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=31
 
}