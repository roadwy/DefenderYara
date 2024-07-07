
rule Trojan_Win32_Dopplof_AR_{
	meta:
		description = "Trojan:Win32/Dopplof.AR!!Dopplof.S1,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 8e d0 bc 00 7c 8e c0 8e d8 be 00 7c bf 00 90 01 df 54 43 50 41 90 01 70 49 6e 76 61 6c 69 64 20 70 61 72 74 69 74 69 6f 6e 20 74 61 62 6c 65 90 01 84 55 aa 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dopplof_AR__2{
	meta:
		description = "Trojan:Win32/Dopplof.AR!!Dopplof.S2,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {02 00 ee fe 90 01 02 01 00 00 00 90 01 34 55 aa 45 46 49 20 50 41 52 54 90 00 } //1
		$a_02_1 = {02 00 ee ff 90 01 02 01 00 00 00 90 01 34 55 aa 45 46 49 20 50 41 52 54 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Dopplof_AR__3{
	meta:
		description = "Trojan:Win32/Dopplof.AR!!Dopplof.S3,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 0e 00 00 "
		
	strings :
		$a_80_0 = {5c 3f 3f 5c 67 6c 6f 62 61 6c 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 64 65 76 69 63 65 5c } //\??\global\globalroot\device\  1
		$a_80_1 = {5c 5c 3f 5c 67 6c 6f 62 61 6c 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 64 65 76 69 63 65 5c } //\\?\global\globalroot\device\  1
		$a_80_2 = {5c 3f 3f 5c 67 6c 6f 62 61 6c 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 67 6c 6f 62 61 6c 3f 3f 5c } //\??\global\globalroot\global??\  1
		$a_80_3 = {5c 5c 3f 5c 67 6c 6f 62 61 6c 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 67 6c 6f 62 61 6c 3f 3f 5c } //\\?\global\globalroot\global??\  1
		$a_80_4 = {5c 3f 3f 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 64 65 76 69 63 65 5c } //\??\globalroot\device\  1
		$a_80_5 = {5c 5c 3f 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 64 65 76 69 63 65 5c } //\\?\globalroot\device\  1
		$a_80_6 = {5c 3f 3f 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 67 6c 6f 62 61 6c 3f 3f 5c } //\??\globalroot\global??\  1
		$a_80_7 = {5c 5c 3f 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 67 6c 6f 62 61 6c 3f 3f 5c } //\\?\globalroot\global??\  1
		$a_02_8 = {5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 64 65 76 69 63 65 5c 68 61 72 64 64 69 73 6b 90 02 03 5c 70 61 72 74 69 74 69 6f 6e 30 90 00 } //1
		$a_02_9 = {5c 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 72 00 6f 00 6f 00 74 00 5c 00 64 00 65 00 76 00 69 00 63 00 65 00 5c 00 68 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 90 02 06 5c 00 70 00 61 00 72 00 74 00 69 00 74 00 69 00 6f 00 6e 00 30 00 90 00 } //1
		$a_80_10 = {5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 64 65 76 69 63 65 5c 63 73 76 } //\globalroot\device\csv  65526
		$a_80_11 = {5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 64 65 76 69 63 65 5c 63 64 72 6f 6d } //\globalroot\device\cdrom  65526
		$a_80_12 = {5c 64 65 76 69 63 65 5c 64 72 6d 75 73 62 64 73 6b 6f 62 6a } //\device\drmusbdskobj  65526
		$a_80_13 = {75 73 62 73 74 6f 72 23 64 69 73 6b 26 76 65 6e 5f 67 65 6e 65 72 69 63 } //usbstor#disk&ven_generic  65526
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_02_8  & 1)*1+(#a_02_9  & 1)*1+(#a_80_10  & 1)*65526+(#a_80_11  & 1)*65526+(#a_80_12  & 1)*65526+(#a_80_13  & 1)*65526) >=1
 
}