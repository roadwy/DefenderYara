
rule Trojan_Win64_SpyBoy_EC_MTB{
	meta:
		description = "Trojan:Win64/SpyBoy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_81_0 = {41 6e 74 69 4d 61 6c 77 61 72 65 5c 62 69 6e 5c 7a 61 6d 36 34 2e 70 64 62 } //2 AntiMalware\bin\zam64.pdb
		$a_81_1 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 5a 65 6d 61 6e 61 41 6e 74 69 4d 61 6c 77 61 72 65 } //2 \DosDevices\ZemanaAntiMalware
		$a_81_2 = {44 72 69 76 65 72 45 6e 74 72 79 28 29 3a 5a 41 4d 20 44 72 69 76 65 72 20 2d 20 76 32 38 36 20 4c 6f 61 64 65 64 } //2 DriverEntry():ZAM Driver - v286 Loaded
		$a_81_3 = {5a 6d 6e 43 6c 6e 44 65 6c 65 74 65 46 69 6c 65 73 50 72 6f 63 65 73 73 6f 72 } //1 ZmnClnDeleteFilesProcessor
		$a_81_4 = {5a 6d 6e 43 6c 6e 43 6f 70 79 46 69 6c 65 73 50 72 6f 63 65 73 73 6f 72 } //1 ZmnClnCopyFilesProcessor
		$a_81_5 = {5a 6d 6e 43 6c 6e 50 72 6f 63 65 73 73 45 6e 74 72 69 65 73 } //1 ZmnClnProcessEntries
		$a_81_6 = {5a 6d 6e 43 6c 6e 52 75 6e 43 6c 65 61 6e 65 72 } //1 ZmnClnRunCleaner
		$a_81_7 = {5a 6d 6e 49 6f 43 72 65 61 74 65 46 69 6c 65 42 79 70 61 73 73 46 69 6c 74 65 72 73 } //1 ZmnIoCreateFileBypassFilters
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=11
 
}