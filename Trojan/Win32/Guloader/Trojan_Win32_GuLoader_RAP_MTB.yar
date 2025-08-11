
rule Trojan_Win32_GuLoader_RAP_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_81_0 = {63 6c 6f 63 6b 20 73 6b 72 6d 73 6b 65 6d 61 65 72 20 64 61 6e 69 63 } //1 clock skrmskemaer danic
		$a_81_1 = {73 6c 75 74 74 65 72 65 64 } //1 sluttered
		$a_81_2 = {65 75 67 65 6e 69 75 73 20 62 65 73 6b 72 69 6e 67 65 72 6e 65 73 } //1 eugenius beskringernes
		$a_81_3 = {61 6d 66 69 62 69 65 74 61 6e 6b 65 6e 65 73 2e 65 78 65 } //1 amfibietankenes.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=2
 
}