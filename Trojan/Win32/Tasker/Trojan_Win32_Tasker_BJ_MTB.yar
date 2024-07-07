
rule Trojan_Win32_Tasker_BJ_MTB{
	meta:
		description = "Trojan:Win32/Tasker.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 0c 3d d2 2e 06 00 77 12 40 89 44 24 0c 3d f8 7c 29 34 0f 82 } //2
		$a_01_1 = {33 c1 89 44 24 10 8b 54 24 10 89 54 24 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}