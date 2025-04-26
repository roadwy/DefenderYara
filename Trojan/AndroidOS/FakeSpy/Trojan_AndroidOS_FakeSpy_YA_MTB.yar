
rule Trojan_AndroidOS_FakeSpy_YA_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeSpy.YA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 65 72 76 6c 65 74 2f 41 70 70 49 6e 66 6f 73 } //1 servlet/AppInfos
		$a_00_1 = {73 65 72 76 6c 65 74 2f 47 65 74 4d 65 73 73 61 67 65 32 } //1 servlet/GetMessage2
		$a_02_2 = {68 74 74 70 3a 2f 2f [0-10] 2e 63 6c 75 62 } //1
		$a_00_3 = {73 64 63 61 72 64 2f 6e 65 77 2e 61 70 6b } //1 sdcard/new.apk
		$a_00_4 = {45 6d 75 6c 61 74 6f 72 22 29 20 3d 3d 20 2d 31 } //1 Emulator") == -1
		$a_00_5 = {6d 79 62 61 6e 6b } //1 mybank
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}