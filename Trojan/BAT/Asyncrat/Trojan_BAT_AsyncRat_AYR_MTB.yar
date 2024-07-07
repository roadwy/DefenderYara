
rule Trojan_BAT_AsyncRat_AYR_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 11 04 09 6f 26 00 00 0a 13 05 06 12 05 28 27 00 00 0a 6f 28 00 00 0a 26 00 11 04 17 58 13 04 11 04 07 fe 02 16 fe 01 13 06 11 06 2d d1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRat_AYR_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.AYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 08 00 00 04 11 09 7e 07 00 00 04 11 09 91 7e 09 00 00 04 11 09 7e 09 00 00 04 8e 69 5d 91 61 d2 9c 11 07 28 90 01 03 0a 00 00 11 0a 17 58 13 0a 11 0a 7e 07 00 00 04 8e 69 fe 04 13 0b 11 0b 2d a7 90 00 } //2
		$a_01_1 = {4e 00 6f 00 50 00 6f 00 77 00 65 00 72 00 } //1 NoPower
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_AsyncRat_AYR_MTB_3{
	meta:
		description = "Trojan:BAT/AsyncRat.AYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {6c 00 69 00 6e 00 6b 00 70 00 69 00 63 00 74 00 75 00 72 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 71 00 2f 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 65 00 64 00 5f 00 31 00 30 00 31 00 2e 00 70 00 6e 00 67 00 } //2 linkpicture.com/q/converted_101.png
		$a_01_1 = {4f 00 70 00 65 00 6e 00 52 00 65 00 61 00 64 00 } //1 OpenRead
		$a_01_2 = {77 69 6e 64 77 6f 73 2e 70 64 62 } //1 windwos.pdb
		$a_01_3 = {54 00 68 00 69 00 73 00 20 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 20 00 69 00 73 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 61 00 6e 00 20 00 75 00 6e 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 6f 00 66 00 20 00 49 00 6e 00 74 00 65 00 6c 00 6c 00 69 00 4c 00 6f 00 63 00 6b 00 } //1 This assembly is protected by an unregistered version of IntelliLock
		$a_01_4 = {77 00 69 00 6e 00 64 00 77 00 6f 00 73 00 2e 00 65 00 78 00 65 00 } //1 windwos.exe
		$a_01_5 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}