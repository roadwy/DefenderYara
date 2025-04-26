
rule TrojanDownloader_O97M_Emotet_PDL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 65 6c 6c 6e 65 73 73 6f 6e 75 73 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 4f 46 71 35 46 38 59 2f } //1 ://wellnessonus.com/wp-admin/OFq5F8Y/
		$a_01_1 = {3a 2f 2f 63 68 6f 69 63 65 70 65 73 74 63 6f 6e 74 72 6f 6c 2e 78 79 7a 2f 77 65 6c 6c 6b 6e 6f 77 6e 2f 50 45 52 4b 6e 4d 34 58 2f } //1 ://choicepestcontrol.xyz/wellknown/PERKnM4X/
		$a_01_2 = {3a 2f 2f 73 73 65 2d 73 74 75 64 69 6f 2e 63 6f 6d 2f 63 71 30 78 68 70 6a 2f 36 70 6d 6d 73 61 50 43 4f 47 74 47 36 2f } //1 ://sse-studio.com/cq0xhpj/6pmmsaPCOGtG6/
		$a_01_3 = {3a 2f 2f 76 65 6c 61 73 61 72 6f 6d 61 74 69 63 61 73 6f 6e 6c 69 6e 65 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 35 49 64 35 4c 71 53 62 33 4f 33 42 55 4d 35 5a 2f } //1 ://velasaromaticasonline.com/wp-admin/5Id5LqSb3O3BUM5Z/
		$a_01_4 = {3a 2f 2f 61 6c 6f 6e 73 6f 63 6f 6e 73 75 6c 74 61 6e 63 79 73 65 72 76 69 63 65 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 30 72 37 74 4d 41 6e 4c 66 77 4b 75 30 67 76 63 48 2f } //1 ://alonsoconsultancyservice.com/wp-content/0r7tMAnLfwKu0gvcH/
		$a_01_5 = {3a 2f 2f 74 72 61 69 6e 69 6e 67 63 68 61 6c 6c 65 6e 67 65 73 2e 78 79 7a 2f 77 70 2d 61 64 6d 69 6e 2f 65 62 50 62 73 4f 64 73 52 4a 41 39 47 2f } //1 ://trainingchallenges.xyz/wp-admin/ebPbsOdsRJA9G/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}