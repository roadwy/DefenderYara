
rule TrojanDownloader_O97M_IcedID_SSB_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.SSB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 2e 50 72 69 6e 74 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 6c 65 6e 56 62 57 69 6e 64 6f 77 28 22 6c 6c 65 68 73 2e 74 70 69 72 63 73 77 22 29 29 2e 52 65 67 57 72 69 74 65 28 61 72 72 50 6f 69 6e 74 65 72 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 29 } //1 Debug.Print CreateObject(lenVbWindow("llehs.tpircsw")).RegWrite(arrPointer, 1, "REG_DWORD")
		$a_01_1 = {6c 6f 63 61 6c 43 61 70 74 69 6f 6e 4d 65 6d 6f 72 79 20 3d 20 4d 69 64 28 6f 70 74 69 6f 6e 45 78 2c 20 63 6f 75 6e 74 65 72 54 65 6d 70 53 74 6f 72 61 67 65 2c 20 31 30 30 30 30 30 30 29 } //1 localCaptionMemory = Mid(optionEx, counterTempStorage, 1000000)
		$a_01_2 = {3d 20 56 42 41 2e 53 74 72 52 65 76 65 72 73 65 28 72 65 71 75 65 73 74 44 6f 63 75 6d 65 6e 74 29 } //1 = VBA.StrReverse(requestDocument)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_IcedID_SSB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/IcedID.SSB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {53 65 74 20 90 02 0f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 56 42 53 63 72 69 70 74 2e 52 65 67 45 78 70 22 29 90 00 } //1
		$a_00_1 = {50 61 74 74 65 72 6e 20 3d 20 22 71 7c 44 7c 54 7c 50 7c 59 7c 77 7c 42 7c 56 7c 55 7c 49 7c 4f 7c 5a 7c 4d 7c 46 7c 58 7c 4e 7c 47 7c 51 7c 4c 7c 4b 7c 7a } //2 Pattern = "q|D|T|P|Y|w|B|V|U|I|O|Z|M|F|X|N|G|Q|L|K|z
		$a_00_2 = {50 61 74 74 65 72 6e 20 3d 20 22 4b 7c 76 7c 71 7c 58 7c 50 7c 5a 7c 6a 7c 4e 7c 46 7c 54 7c 42 7c 59 7c 4c 7c 7a 7c 55 7c 48 7c 77 7c 56 7c 44 7c 4f 7c 47 } //2 Pattern = "K|v|q|X|P|Z|j|N|F|T|B|Y|L|z|U|H|w|V|D|O|G
		$a_00_3 = {2e 52 65 70 6c 61 63 65 28 58 4b 55 35 6e 4f 66 4b 71 44 28 30 29 2c 20 22 22 29 } //2 .Replace(XKU5nOfKqD(0), "")
		$a_00_4 = {2e 52 65 70 6c 61 63 65 28 74 79 65 61 48 66 28 30 29 2c 20 22 22 29 } //2 .Replace(tyeaHf(0), "")
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=5
 
}