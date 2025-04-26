
rule Ransom_MSIL_Filecoder_AK_ibt{
	meta:
		description = "Ransom:MSIL/Filecoder.AK!ibt,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //System.Security.Cryptography  1
		$a_80_1 = {65 6d 64 39 61 6c 70 34 4b 45 45 43 45 32 55 4b 54 77 55 52 48 6e 34 57 64 67 45 43 59 48 5a 63 57 6a 35 34 57 42 42 47 63 6e 6f } //emd9alp4KEECE2UKTwURHn4WdgECYHZcWj54WBBGcno  1
		$a_80_2 = {4e 52 4a 58 63 4b 6d 79 46 50 53 4f 77 47 57 58 4e 57 43 42 43 50 44 6b 6e 7a 41 69 52 70 41 4b } //NRJXcKmyFPSOwGWXNWCBCPDknzAiRpAK  1
		$a_80_3 = {48 47 56 78 42 68 4a 63 58 56 38 52 5a 45 42 6b 42 6e 6c 77 61 69 41 49 61 56 41 71 66 69 31 4b 44 42 74 54 56 77 74 39 57 6d 41 } //HGVxBhJcXV8RZEBkBnlwaiAIaVAqfi1KDBtTVwt9WmA  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}