
rule Trojan_Win32_Emotet_AW_MSR{
	meta:
		description = "Trojan:Win32/Emotet.AW!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {6c 69 62 67 63 6a 2d 31 32 2e 64 6c 6c } //1 libgcj-12.dll
		$a_01_1 = {53 65 74 46 69 6c 65 53 65 63 75 72 69 74 79 57 } //1 SetFileSecurityW
		$a_01_2 = {42 72 6f 6b 65 6e 20 70 72 6f 6d 69 73 65 } //1 Broken promise
		$a_01_3 = {50 72 6f 6d 69 73 65 20 61 6c 72 65 61 64 79 20 73 61 74 69 73 66 69 65 64 } //1 Promise already satisfied
		$a_01_4 = {6d 78 33 79 6a 7b 73 47 6d 4f 6a 5a 7d 58 58 } //1 mx3yj{sGmOjZ}XX
		$a_01_5 = {70 6c 61 79 2e 73 68 70 } //1 play.shp
		$a_01_6 = {5a 6a 78 53 53 65 6f 42 4f 71 4c 6a } //1 ZjxSSeoBOqLj
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}