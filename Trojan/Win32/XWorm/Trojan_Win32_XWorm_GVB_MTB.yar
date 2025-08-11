
rule Trojan_Win32_XWorm_GVB_MTB{
	meta:
		description = "Trojan:Win32/XWorm.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 1c 02 88 1c 01 83 c0 01 83 d6 00 90 13 3d d7 08 00 00 89 f7 83 df } //2
		$a_02_1 = {89 f3 83 e3 07 8a 1c 1c 80 f3 4a 88 1c 32 83 c6 01 83 d7 00 90 13 39 ce 89 fb 19 c3 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}