
rule Trojan_Win64_DarkShellLoader_LK_MTB{
	meta:
		description = "Trojan:Win64/DarkShellLoader.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d1 e8 03 c2 c1 e8 05 0f b7 c0 6b c8 37 41 0f b7 c0 66 2b c1 66 83 c0 36 66 41 31 01 41 ff c0 4d 8d 49 02 41 83 f8 10 7c ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}