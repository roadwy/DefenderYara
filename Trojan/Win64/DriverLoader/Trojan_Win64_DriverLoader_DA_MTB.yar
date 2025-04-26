
rule Trojan_Win64_DriverLoader_DA_MTB{
	meta:
		description = "Trojan:Win64/DriverLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {49 00 4e 00 4a 00 45 00 43 00 54 00 4f 00 52 00 [0-01] 5c 00 78 00 36 00 34 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 70 00 64 00 62 00 } //10
		$a_03_1 = {49 4e 4a 45 43 54 4f 52 [0-01] 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 2e 70 64 62 } //10
		$a_81_2 = {2f 2f 6d 65 67 61 2e 6e 7a 2f 66 69 6c 65 2f } //1 //mega.nz/file/
		$a_81_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 70 72 6f 63 65 73 73 68 61 63 6b 65 72 } //1 taskkill /FI "IMAGENAME eq processhacker
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=11
 
}