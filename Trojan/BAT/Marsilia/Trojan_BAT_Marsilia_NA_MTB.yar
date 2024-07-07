
rule Trojan_BAT_Marsilia_NA_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 07 11 07 2c 0c 00 11 05 1a 5a 11 06 58 13 04 } //10 ܓܑబᄀᨅᅚ堆Г
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_BAT_Marsilia_NA_MTB_2{
	meta:
		description = "Trojan:BAT/Marsilia.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {65 6e 63 72 79 70 74 65 64 42 79 74 65 73 } //encryptedBytes  1
		$a_80_1 = {64 65 63 72 79 70 74 65 64 54 65 78 74 } //decryptedText  1
		$a_80_2 = {4d 53 4f 66 66 69 63 65 52 75 6e 4f 6e 63 65 6c 73 6c 73 } //MSOfficeRunOncelsls  1
		$a_80_3 = {64 65 6c 65 74 65 76 61 6c 75 65 20 7b 64 65 66 61 75 6c 74 7d 20 73 61 66 65 62 6f 6f 74 } //deletevalue {default} safeboot  1
		$a_80_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 48 65 6c 70 } //C:\Windows\Help  1
		$a_80_5 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 48 65 6c 70 5c 50 61 79 2e 74 78 74 } //C:\Windows\Help\Pay.txt  1
		$a_80_6 = {54 68 69 73 49 73 53 74 61 67 65 32 } //ThisIsStage2  1
		$a_80_7 = {72 6f 6f 74 5c 57 4d 49 3a 42 63 64 4f 62 6a 65 63 74 2e 49 64 3d } //root\WMI:BcdObject.Id=  1
		$a_80_8 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 5c 4e 65 74 77 6f 72 6b } //SYSTEM\CurrentControlSet\Control\SafeBoot\Network  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}