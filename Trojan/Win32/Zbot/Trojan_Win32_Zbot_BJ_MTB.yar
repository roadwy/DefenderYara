
rule Trojan_Win32_Zbot_BJ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c6 03 c7 89 45 ec 8b 45 ec 2b c7 33 c6 89 45 ec 8b 45 ec 8b 4d e8 3b c8 0f 85 } //1
		$a_01_1 = {33 c8 33 d0 2b ca 2b ce 33 c8 89 4d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}