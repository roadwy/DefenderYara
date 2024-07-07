
rule TrojanDownloader_O97M_Trickbot_PVZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Trickbot.PVZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 74 75 64 69 6f 66 63 41 } //1 studiofcA
		$a_00_1 = {6f 70 6b 6a 78 63 6e 61 72 74 66 63 6f 70 6b 6a 78 63 6e 61 72 71 75 69 74 66 63 6f 70 6b 6a 78 63 6e 65 74 75 72 66 63 6f 70 6b 6a 78 63 6e 61 2e 63 6f 6d 2e 62 72 2f 77 70 2d 69 6e 63 6c 75 64 } //1 opkjxcnartfcopkjxcnarquitfcopkjxcneturfcopkjxcna.com.br/wp-includ
		$a_00_2 = {66 63 6f 70 6b 6a 78 63 6e 65 73 2f 49 44 33 2f 31 2f 49 4d 47 5f 53 63 66 63 6f 70 6b 6a 78 63 6e 61 6e 6e 66 63 6f 70 6b 6a 78 63 6e 65 64 5f 30 35 32 32 2e 70 64 66 } //1 fcopkjxcnes/ID3/1/IMG_Scfcopkjxcnannfcopkjxcned_0522.pdf
		$a_00_3 = {74 6d 70 5c 5c 79 77 68 78 69 64 72 71 6a 6f 6a 2e 66 63 6f 70 6b 6a 78 63 6e 65 78 66 63 6f 70 6b 6a 78 63 6e 65 } //1 tmp\\ywhxidrqjoj.fcopkjxcnexfcopkjxcne
		$a_00_4 = {53 74 66 63 6f 70 6b 6a 78 63 6e 61 72 74 2d 42 69 74 73 54 72 66 63 6f 70 6b 6a 78 63 6e 61 6e 73 66 66 63 6f 70 6b 6a 78 63 6e 65 72 } //1 Stfcopkjxcnart-BitsTrfcopkjxcnansffcopkjxcner
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}