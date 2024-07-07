
rule Trojan_Win32_RedLineStealer_F_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 55 62 78 78 62 71 74 71 } //1 AUbxxbqtq
		$a_01_1 = {5c 44 6f 77 6e 6c 6f 61 64 73 5c 4e 65 77 50 75 62 6c 69 73 68 5c } //1 \Downloads\NewPublish\
		$a_01_2 = {65 00 76 00 6a 00 6f 00 75 00 73 00 66 00 } //1 evjousf
		$a_01_3 = {6e 00 63 00 6f 00 73 00 73 00 79 00 61 00 } //1 ncossya
		$a_01_4 = {41 70 70 50 6f 6c 69 63 79 47 65 74 50 72 6f 63 65 73 73 54 65 72 6d 69 6e 61 74 69 6f 6e 4d 65 74 68 6f 64 } //1 AppPolicyGetProcessTerminationMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}