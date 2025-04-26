
rule TrojanDownloader_O97M_Emotet_ADPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.ADPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 77 77 2e 6c 69 62 63 75 73 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 75 59 39 53 71 38 31 63 71 4e 77 31 4d 4d 2f } //1 ://www.libcus.com/wp-admin/uY9Sq81cqNw1MM/
		$a_01_1 = {3a 2f 2f 6b 72 6f 6e 6f 73 74 72 2e 63 6f 6d 2f 74 72 2f 62 62 52 6a 45 75 42 46 59 42 58 34 4f 69 6f 64 2f } //1 ://kronostr.com/tr/bbRjEuBFYBX4Oiod/
		$a_01_2 = {3a 2f 2f 6b 75 6c 75 63 6b 61 63 69 2e 63 6f 6d 2f 79 61 72 69 73 6d 61 2f 63 67 69 2d 62 69 6e 2f 6f 62 45 50 76 34 30 69 4e 52 75 6d 68 50 47 76 36 77 6f 2f } //1 ://kuluckaci.com/yarisma/cgi-bin/obEPv40iNRumhPGv6wo/
		$a_01_3 = {3a 2f 2f 6c 69 67 68 74 69 6e 64 75 73 74 72 79 2e 74 76 2f 4a 65 72 65 6d 79 2f 39 76 65 49 37 2f } //1 ://lightindustry.tv/Jeremy/9veI7/
		$a_01_4 = {3a 2f 2f 6c 69 73 61 64 61 76 69 65 2e 63 6f 6d 2f 36 6c 47 42 48 6b 79 4a 33 57 6f 49 35 2f } //1 ://lisadavie.com/6lGBHkyJ3WoI5/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}