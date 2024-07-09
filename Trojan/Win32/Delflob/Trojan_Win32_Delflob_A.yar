
rule Trojan_Win32_Delflob_A{
	meta:
		description = "Trojan:Win32/Delflob.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_03_0 = {49 45 2b 44 45 46 45 4e 44 45 52 00 [0-30] 4b 41 53 50 45 52 53 4b 59 00 [0-50] 4d 43 41 46 45 45 00 } //10
		$a_00_1 = {69 65 64 65 66 65 6e 64 65 72 2e 63 6f 6d 00 } //1
		$a_01_2 = {64 69 76 78 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 } //1
		$a_00_3 = {00 6c 69 76 65 2e 63 6f 6d 00 } //1
		$a_01_4 = {43 6f 6e 76 65 72 74 53 74 72 69 6e 67 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 54 6f 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 41 } //1 ConvertStringSecurityDescriptorToSecurityDescriptorA
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}