
rule Worm_Win32_Lightmoon_H{
	meta:
		description = "Worm:Win32/Lightmoon.H,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 65 77 4d 6f 6f 6e 6c 69 67 68 74 } //1 NewMoonlight
		$a_01_1 = {6b 65 79 6c 6f 67 } //1 keylog
		$a_01_2 = {53 63 61 6e 45 6d 61 69 6c } //1 ScanEmail
		$a_01_3 = {44 00 61 00 74 00 61 00 48 00 65 00 6c 00 6c 00 53 00 70 00 61 00 77 00 6e 00 5c 00 57 00 41 00 52 00 49 00 4e 00 47 00 5f 00 56 00 49 00 52 00 49 00 49 00 5f 00 4c 00 41 00 42 00 4f 00 52 00 41 00 54 00 4f 00 52 00 59 00 5c 00 56 00 69 00 72 00 75 00 73 00 20 00 4b 00 75 00 5c 00 4d 00 6f 00 6f 00 6e 00 6c 00 69 00 67 00 68 00 74 00 } //1 DataHellSpawn\WARING_VIRII_LABORATORY\Virus Ku\Moonlight
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}