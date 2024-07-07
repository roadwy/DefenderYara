
rule TrojanDownloader_O97M_Qakbot_PDL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 6c 62 6c 6f 67 64 65 6c 6f 73 63 61 63 68 61 6e 69 6c 6c 61 73 2e 63 6f 6d 2e 6d 78 2f 53 33 73 59 38 52 51 31 30 2f 4f 70 68 6e 2e 70 6e 67 } //1 elblogdeloscachanillas.com.mx/S3sY8RQ10/Ophn.png
		$a_01_1 = {6c 61 6c 75 61 6c 65 78 2e 63 6f 6d 2f 41 70 55 55 42 70 31 63 63 64 2f 4f 70 68 6e 2e 70 6e 67 } //1 lalualex.com/ApUUBp1ccd/Ophn.png
		$a_01_2 = {6c 69 7a 65 74 79 2e 63 6f 6d 2f 6d 4a 59 76 70 6f 32 78 68 78 2f 4f 70 68 6e 2e 70 6e 67 } //1 lizety.com/mJYvpo2xhx/Ophn.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}