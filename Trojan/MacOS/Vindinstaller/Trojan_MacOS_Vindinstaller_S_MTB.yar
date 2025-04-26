
rule Trojan_MacOS_Vindinstaller_S_MTB{
	meta:
		description = "Trojan:MacOS/Vindinstaller.S!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {76 69 64 69 6e 73 74 61 6c 6c 65 72 2f 76 69 64 69 6e 73 74 61 6c 6c 65 72 20 70 72 6f 6a 65 63 74 2f } //2 vidinstaller/vidinstaller project/
		$a_00_1 = {73 65 74 63 61 6e 61 64 61 67 72 65 61 75 6b 74 2e 69 6e 66 6f } //2 setcanadagreaukt.info
		$a_00_2 = {43 6f 70 79 72 69 67 68 74 20 31 39 39 38 2d 32 30 30 34 20 47 69 6c 6c 65 73 20 56 6f 6c 6c 61 6e 74 } //1 Copyright 1998-2004 Gilles Vollant
		$a_00_3 = {58 33 35 39 36 5a 39 36 34 38 31 } //1 X3596Z96481
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}