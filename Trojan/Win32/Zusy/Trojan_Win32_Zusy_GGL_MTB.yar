
rule Trojan_Win32_Zusy_GGL_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 4f 04 03 ce 33 0c 30 e8 90 01 04 8b 47 08 8b 4f 0c 03 ce 33 0c 30 90 00 } //10
		$a_80_1 = {50 72 6f 63 65 73 73 20 68 6f 6c 6c 6f 77 69 6e 67 20 63 6f 6d 70 6c 65 74 65 } //Process hollowing complete  1
		$a_80_2 = {73 76 63 68 6f 73 74 } //svchost  1
		$a_80_3 = {70 61 75 73 65 } //pause  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}