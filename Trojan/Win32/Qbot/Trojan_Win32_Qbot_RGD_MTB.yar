
rule Trojan_Win32_Qbot_RGD_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {69 c9 09 b5 00 00 90 01 06 81 ea 09 b5 00 00 90 00 } //1
		$a_02_1 = {83 e9 03 89 0d 90 01 04 8b 15 90 01 04 2b 15 90 01 04 89 15 90 01 04 a1 90 01 04 03 05 90 01 04 a3 90 01 04 83 3d 90 01 04 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_RGD_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {05 c2 5a 00 00 8b 4d 90 01 01 8b 11 2b d0 8b 45 90 01 01 89 10 8b e5 5d 90 00 } //2
		$a_02_1 = {33 c1 8b ff c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b ff 8b 15 90 01 04 a1 90 01 04 89 02 5f 5d 90 00 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}