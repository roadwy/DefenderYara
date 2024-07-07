
rule TrojanDownloader_O97M_IcedID_RVG_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.RVG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {33 30 2e 33 2e 31 31 2e 32 33 2e 32 30 2e 39 2e 33 30 2e 39 } //1 30.3.11.23.20.9.30.9
		$a_00_1 = {53 68 65 6c 6c 20 61 58 44 70 78 20 26 20 22 20 22 20 26 20 61 48 59 45 43 } //1 Shell aXDpx & " " & aHYEC
		$a_00_2 = {4d 69 64 28 61 39 57 49 44 78 2c 20 61 4c 34 63 66 2c 20 31 29 } //1 Mid(a9WIDx, aL4cf, 1)
		$a_00_3 = {53 70 6c 69 74 28 61 5a 76 6a 64 55 2c 20 22 2e 22 29 } //1 Split(aZvjdU, ".")
		$a_00_4 = {4f 70 65 6e 20 61 41 79 6b 42 33 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 } //1 Open aAykB3 For Output As #1
		$a_00_5 = {50 72 69 6e 74 20 23 31 2c 20 61 46 6c 32 50 } //1 Print #1, aFl2P
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}