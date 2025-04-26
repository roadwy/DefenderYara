
rule Trojan_Win64_DriverLoader_DC_MTB{
	meta:
		description = "Trojan:Win64/DriverLoader.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 54 61 73 6b 6d 67 72 2e 65 78 65 } //1 taskkill /FI "IMAGENAME eq Taskmgr.exe
		$a_81_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 70 72 6f 63 65 73 73 68 61 63 6b 65 72 2e 65 78 65 } //1 taskkill /FI "IMAGENAME eq processhacker.exe
		$a_81_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 69 64 61 2e 65 78 65 } //1 taskkill /FI "IMAGENAME eq ida.exe
		$a_81_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 64 6e 53 70 79 2e 65 78 65 } //1 taskkill /FI "IMAGENAME eq dnSpy.exe
		$a_81_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 4b 73 44 75 6d 70 65 72 2e 65 78 65 } //1 taskkill /FI "IMAGENAME eq KsDumper.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}