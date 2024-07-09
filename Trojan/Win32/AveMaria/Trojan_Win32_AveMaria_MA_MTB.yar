
rule Trojan_Win32_AveMaria_MA_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 00 68 84 00 00 00 6a 02 6a 00 6a 01 68 00 00 00 10 68 58 37 40 00 ff 15 ?? ?? ?? ?? 6a 00 8b f0 8d 85 e8 fb ff ff 50 ff 35 2c 33 40 00 ff 35 54 37 40 00 56 ff 15 } //1
		$a_01_1 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_3 = {5c 00 54 00 45 00 4d 00 50 00 5c 00 65 00 6c 00 6c 00 6f 00 63 00 6e 00 61 00 6b 00 2e 00 78 00 6d 00 6c 00 } //1 \TEMP\ellocnak.xml
		$a_01_4 = {5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 33 00 32 00 5c 00 70 00 6b 00 67 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 } //1 \WINDOWS\SYSTEM32\pkgmgr.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}