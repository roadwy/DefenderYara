
rule TrojanDownloader_O97M_Emotet_PDN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 72 6f 73 79 77 68 69 74 65 63 6c 65 61 6e 69 6e 67 73 6f 6c 75 74 69 6f 6e 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 50 71 4d 77 36 66 4e 44 38 42 62 31 49 34 56 50 52 31 30 2f } //1 ://rosywhitecleaningsolution.com/wp-admin/PqMw6fND8Bb1I4VPR10/
		$a_01_1 = {3a 2f 2f 68 61 76 69 6c 61 68 6f 6c 75 65 6d 67 6c 6f 62 61 6c 2e 63 6f 6d 2f 64 6f 66 7a 32 39 2f 79 6d 49 66 43 63 45 4c 38 49 35 6b 6a 41 36 45 2f } //1 ://havilaholuemglobal.com/dofz29/ymIfCcEL8I5kjA6E/
		$a_01_2 = {3a 2f 2f 77 77 77 2e 66 6c 6f 72 65 73 67 75 69 74 61 72 69 6e 73 74 72 75 63 74 69 6f 6e 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 6a 57 6c 43 58 2f } //1 ://www.floresguitarinstruction.com/wp-admin/jWlCX/
		$a_01_3 = {3a 2f 2f 77 77 77 2e 64 72 63 63 2e 63 6f 2e 7a 61 2f 72 65 73 74 6f 72 65 64 63 6f 6e 74 65 6e 74 2f 6e 41 4b 76 6e 62 52 70 61 7a 78 37 63 2f } //1 ://www.drcc.co.za/restoredcontent/nAKvnbRpazx7c/
		$a_01_4 = {3a 2f 2f 61 6f 70 64 61 2e 6f 72 67 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 52 44 4c 37 35 50 4d 45 37 4f 4b 48 6b 34 66 2f } //1 ://aopda.org/wp-content/uploads/RDL75PME7OKHk4f/
		$a_01_5 = {3a 2f 2f 63 68 65 72 61 2e 63 6f 2e 6b 72 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 69 32 6e 6e 55 6b 44 58 5a 2f } //1 ://chera.co.kr/wp-includes/i2nnUkDXZ/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}