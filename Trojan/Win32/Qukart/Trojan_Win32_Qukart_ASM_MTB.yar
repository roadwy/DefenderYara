
rule Trojan_Win32_Qukart_ASM_MTB{
	meta:
		description = "Trojan:Win32/Qukart.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6c 4c 6f 6a 45 59 74 59 2b } //1 lLojEYtY+
		$a_01_1 = {70 6b 63 50 7a 74 6e 58 } //1 pkcPztnX
		$a_01_2 = {6b 76 63 4c 64 6d 51 6a } //1 kvcLdmQj
		$a_01_3 = {44 45 52 75 79 59 71 4c 62 } //1 DERuyYqLb
		$a_01_4 = {68 79 69 45 4e 64 46 6d } //1 hyiENdFm
		$a_01_5 = {64 51 55 73 46 46 43 69 } //1 dQUsFFCi
		$a_01_6 = {44 58 45 48 48 5a 64 79 } //1 DXEHHZdy
		$a_01_7 = {4e 79 66 49 6b 52 49 46 } //1 NyfIkRIF
		$a_01_8 = {78 6c 6e 76 6d 4d 64 65 } //1 xlnvmMde
		$a_01_9 = {77 56 69 68 6f 48 59 71 72 } //1 wVihoHYqr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}