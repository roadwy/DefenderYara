
rule Trojan_BAT_Tedy_ATD_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ATD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 1f 0c 13 07 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Tedy_ATD_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.ATD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a2 25 17 28 13 00 00 0a a2 25 18 72 e5 00 00 70 a2 25 19 28 14 00 00 0a a2 25 1a 72 fb 00 00 70 a2 25 1b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Tedy_ATD_MTB_3{
	meta:
		description = "Trojan:BAT/Tedy.ATD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 04 11 04 13 05 11 05 13 06 16 13 07 2b 19 00 09 06 07 11 07 91 06 8e 69 5d 93 6f 6d 00 00 0a 26 00 11 07 17 d6 13 07 11 07 11 06 fe 02 16 fe 01 13 08 11 08 2d d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Tedy_ATD_MTB_4{
	meta:
		description = "Trojan:BAT/Tedy.ATD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 04 08 06 1a 06 8e b7 1a da 6f 3a 00 00 0a 11 04 17 da 17 d6 8d 2f 00 00 01 0d 08 16 6a 6f 3b 00 00 0a 08 16 73 3c 00 00 0a 13 05 11 05 09 16 09 8e b7 } //2
		$a_01_1 = {6c 00 6f 00 76 00 65 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 68 00 61 00 70 00 70 00 79 00 } //1 loveInvokehappy
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Tedy_ATD_MTB_5{
	meta:
		description = "Trojan:BAT/Tedy.ATD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 61 00 00 70 28 ?? ?? ?? 06 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0b dd 03 00 00 00 26 de d6 } //1
		$a_01_1 = {16 0a 02 8e 69 17 59 0b 38 16 00 00 00 02 06 91 0c 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32 e6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Tedy_ATD_MTB_6{
	meta:
		description = "Trojan:BAT/Tedy.ATD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b 28 00 06 28 ?? ?? ?? 06 0b 07 20 01 80 00 00 fe 01 0c 08 2c 0f 00 7e ?? ?? ?? 04 06 d1 6f ?? ?? ?? 0a 26 00 00 06 17 58 } //2
		$a_01_1 = {43 61 70 74 75 72 65 41 6e 64 53 61 76 65 53 63 72 65 65 6e 73 68 6f 74 } //1 CaptureAndSaveScreenshot
		$a_01_2 = {4e 00 75 00 65 00 76 00 61 00 20 00 63 00 61 00 72 00 70 00 65 00 74 00 61 00 5c 00 6c 00 6f 00 67 00 73 00 2e 00 74 00 78 00 74 00 } //1 Nueva carpeta\logs.txt
		$a_01_3 = {4e 00 75 00 65 00 76 00 61 00 20 00 63 00 61 00 72 00 70 00 65 00 74 00 61 00 5c 00 73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 2e 00 70 00 6e 00 67 00 } //1 Nueva carpeta\screenshot.png
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}