
rule Trojan_Win32_LummaC_NFS_MTB{
	meta:
		description = "Trojan:Win32/LummaC.NFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 c8 21 f8 89 da 21 f2 0f a4 c2 01 01 c0 01 f9 11 f3 89 d6 31 de 89 c7 31 cf f7 d2 f7 d0 21 c8 21 da } //1
		$a_03_1 = {01 f1 fe c1 89 c6 0f ad d6 89 d7 d3 ef f6 c1 ?? ?? ?? 89 fe 31 ff 31 d7 31 c6 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}