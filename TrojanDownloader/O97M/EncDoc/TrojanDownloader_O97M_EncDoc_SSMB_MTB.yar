
rule TrojanDownloader_O97M_EncDoc_SSMB_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SSMB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 4f 56 49 44 2d 31 39 20 46 75 6e 65 72 61 6c 20 41 73 73 69 73 74 61 6e 63 65 20 48 65 6c 70 6c 69 6e 65 20 38 34 34 2d 36 38 34 2d 36 33 33 33 } //01 00  COVID-19 Funeral Assistance Helpline 844-684-6333
		$a_01_1 = {4a 4a 43 43 43 4a 4a } //05 00  JJCCCJJ
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 51 42 75 62 54 63 44 68 64 65 64 58 4a 62 74 79 51 64 78 68 64 2e 72 74 66 } //05 00  C:\ProgramData\QBubTcDhdedXJbtyQdxhd.rtf
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 66 69 71 72 45 6c 6b 57 78 62 4b 54 79 4b 43 61 59 70 51 4b 75 6a 66 70 56 68 4d 2e 72 74 66 } //05 00  C:\ProgramData\fiqrElkWxbKTyKCaYpQKujfpVhM.rtf
		$a_01_4 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 61 64 54 43 55 6d 49 69 6e 77 44 2e 72 74 66 } //05 00  C:\ProgramData\adTCUmIinwD.rtf
		$a_01_5 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 47 5a 49 67 43 49 6d 42 69 4d 6c 59 54 67 52 52 76 } //05 00  C:\ProgramData\GZIgCImBiMlYTgRRv
		$a_01_6 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 71 63 48 6e 4b 64 45 67 4b 4b 4d 71 49 77 54 65 63 76 50 67 6b 51 5a } //00 00  C:\ProgramData\qcHnKdEgKKMqIwTecvPgkQZ
	condition:
		any of ($a_*)
 
}