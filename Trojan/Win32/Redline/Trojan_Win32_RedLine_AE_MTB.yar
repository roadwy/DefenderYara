
rule Trojan_Win32_RedLine_AE_MTB{
	meta:
		description = "Trojan:Win32/RedLine.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c2 83 e0 03 0f b6 80 [0-04] 30 82 [0-04] 8d 86 } //2
		$a_03_1 = {03 c2 83 e0 03 0f b6 80 [0-04] 30 82 [0-04] 83 c2 04 81 fa 00 ac 01 00 72 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}