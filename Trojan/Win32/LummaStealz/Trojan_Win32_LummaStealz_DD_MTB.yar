
rule Trojan_Win32_LummaStealz_DD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealz.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {63 32 73 6f 63 6b } //1 c2sock
		$a_81_1 = {63 32 63 6f 6e 66 } //1 c2conf
		$a_81_2 = {6c 69 64 3d 25 73 } //1 lid=%s
		$a_03_3 = {2f 4c 75 6d [0-3c] 43 32 [0-20] 42 75 69 6c 64 } //1
		$a_81_4 = {54 65 73 6c 61 42 72 6f 77 73 65 72 } //1 TeslaBrowser
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_03_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}