
rule Backdoor_Win32_Zegost_AJ{
	meta:
		description = "Backdoor:Win32/Zegost.AJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {c6 45 cc 57 c6 45 cd 49 c6 45 ce 4e c6 45 cf 4d c6 45 d0 4d c6 45 d1 2e c6 45 d2 64 c6 45 d3 6c c6 45 d4 6c } //1
		$a_01_1 = {c6 85 70 fd ff ff 53 c6 85 71 fd ff ff 4f c6 85 72 fd ff ff 46 c6 85 73 fd ff ff 54 c6 85 74 fd ff ff 57 c6 85 75 fd ff ff 41 c6 85 76 fd ff ff 52 } //1
		$a_01_2 = {43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 4e 65 77 73 25 69 25 69 25 69 2e 64 6f 63 00 } //1
		$a_01_3 = {00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 } //1
		$a_01_4 = {00 5b 43 61 70 73 4c 6f 63 6b 5d 00 } //1 嬀慃獰潌正]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}