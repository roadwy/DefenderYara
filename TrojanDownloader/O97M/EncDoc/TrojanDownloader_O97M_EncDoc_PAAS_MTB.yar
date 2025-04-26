
rule TrojanDownloader_O97M_EncDoc_PAAS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAAS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 69 64 6f 72 63 61 72 6c 6f 73 79 64 61 76 69 64 2e 65 73 2f 77 70 2d 61 64 6d 69 6e 2f 6a 6b 4e 50 67 48 78 4e 6a 46 } //1 servidorcarlosydavid.es/wp-admin/jkNPgHxNjF
		$a_01_1 = {67 6d 6f 2d 73 6f 6c 2d 70 31 30 2e 68 65 74 65 6d 6c 2e 6a 70 2f 69 6e 63 6c 75 64 65 73 2f 55 6f 4a 4d 67 59 41 63 31 45 45 53 } //1 gmo-sol-p10.heteml.jp/includes/UoJMgYAc1EES
		$a_01_2 = {69 61 73 68 61 6e 67 68 61 69 2e 63 6e 2f 7a 2f 5a 31 50 47 36 75 6c 42 68 32 30 70 6c 73 73 } //1 iashanghai.cn/z/Z1PG6ulBh20plss
		$a_01_3 = {70 61 73 69 6f 6e 70 6f 72 74 75 66 75 74 75 72 6f 2e 70 65 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 48 6b 55 66 76 77 30 78 75 43 79 35 } //1 pasionportufuturo.pe/wp-content/HkUfvw0xuCy5
		$a_01_4 = {64 6d 64 61 67 65 6e 74 73 2e 63 6f 6d 2e 61 75 2f 76 71 77 62 67 7a 2f 43 4c 34 42 6f 34 43 34 56 53 30 64 65 67 } //1 dmdagents.com.au/vqwbgz/CL4Bo4C4VS0deg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}