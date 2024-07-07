
rule TrojanDownloader_O97M_Emotet_PDI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6e 61 74 61 6c 69 61 70 65 72 65 69 72 61 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 70 45 38 78 59 59 33 78 36 70 2f } //1 ://nataliapereira.com/wp-admin/pE8xYY3x6p/
		$a_01_1 = {3a 2f 2f 61 6e 6e 65 77 65 6c 73 68 73 61 6c 6f 6e 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 32 63 39 6c 32 6f 31 2f 63 57 57 41 7a 54 56 51 2f } //1 ://annewelshsalon.com/wp-admin/2c9l2o1/cWWAzTVQ/
		$a_01_2 = {3a 2f 2f 68 65 6c 6c 6f 63 6c 6f 75 64 67 75 72 75 73 67 65 72 61 6c 64 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 69 58 59 78 2f } //1 ://hellocloudgurusgerald.com/wp-content/iXYx/
		$a_01_3 = {3a 2f 2f 72 61 6d 69 6a 61 62 61 6c 69 2e 63 6f 6d 2f 6c 69 63 65 6e 73 65 73 2f } //1 ://ramijabali.com/licenses/
		$a_01_4 = {3a 2f 2f 61 66 72 69 63 61 2d 72 6f 61 64 77 6f 72 6b 73 2e 63 6f 6d 2f 6c 69 6c 6f 2d 62 61 72 64 2f 76 6b 33 47 53 59 37 2f } //1 ://africa-roadworks.com/lilo-bard/vk3GSY7/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}