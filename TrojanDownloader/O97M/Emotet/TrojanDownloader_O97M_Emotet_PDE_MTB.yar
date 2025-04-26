
rule TrojanDownloader_O97M_Emotet_PDE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 61 6a 6d 6f 74 6f 72 73 73 68 6f 70 2e 63 6f 6d 2f 67 72 61 64 2d 6f 6f 7a 65 2f 4f 2f } //1 ://ajmotorsshop.com/grad-ooze/O/
		$a_01_1 = {3a 2f 2f 6d 73 75 62 72 61 68 6d 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 35 53 6a 42 70 39 57 48 66 47 62 74 67 59 2f } //1 ://msubrahm.com/wp-admin/5SjBp9WHfGbtgY/
		$a_01_2 = {3a 2f 2f 6d 6f 76 65 63 6f 6e 6e 65 63 74 73 2e 63 6f 6d 2f 69 74 65 6d 2d 69 6d 6d 6f 2f 35 4e 41 74 4d 58 58 43 6b 7a 51 35 4e 72 58 33 7a 2f 39 6d 6f 65 54 69 65 34 76 48 4a 2f } //1 ://moveconnects.com/item-immo/5NAtMXXCkzQ5NrX3z/9moeTie4vHJ/
		$a_01_3 = {3a 2f 2f 62 65 74 61 32 2e 65 6d 65 72 69 74 75 73 2e 6f 72 67 2f 77 70 2d 63 6f 6e 74 65 6e 74 2e 70 72 65 76 69 6f 75 73 2f 57 53 30 4f 2f } //1 ://beta2.emeritus.org/wp-content.previous/WS0O/
		$a_01_4 = {3a 2f 2f 6b 61 72 6d 61 70 65 64 69 61 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 65 64 76 66 2f } //1 ://karmapedia.com/wp-includes/edvf/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}