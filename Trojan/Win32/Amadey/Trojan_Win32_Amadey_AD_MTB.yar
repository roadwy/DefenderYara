
rule Trojan_Win32_Amadey_AD_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 55 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 4d ff 03 4d 94 88 4d ff 0f b6 55 ff f7 da 88 55 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Amadey_AD_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b cb 33 d2 8b c1 f7 f6 83 c2 90 01 01 66 31 54 4d b8 41 83 f9 90 00 } //1
		$a_03_1 = {8b cb 5e 33 d2 8b c1 f7 f6 80 c2 90 01 01 30 54 0d 98 41 83 f9 90 00 } //1
		$a_01_2 = {25 00 77 00 69 00 6e 00 64 00 69 00 72 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 25 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 25 00 5c 00 75 00 70 00 64 00 61 00 74 00 65 00 54 00 61 00 73 00 6b 00 2e 00 64 00 6c 00 6c 00 2c 00 20 00 45 00 6e 00 74 00 72 00 79 00 } //1 %windir%\system32\rundll32.exe %programdata%\updateTask.dll, Entry
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}