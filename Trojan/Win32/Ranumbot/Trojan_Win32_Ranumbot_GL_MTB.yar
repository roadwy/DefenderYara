
rule Trojan_Win32_Ranumbot_GL_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c6 33 c8 8d 90 01 01 24 90 02 04 e8 90 0a 64 00 8b 90 01 01 c1 90 01 01 05 c7 05 90 01 08 c7 05 90 01 04 ff ff ff ff 89 90 01 01 24 90 01 01 8b 90 01 01 24 90 02 04 01 90 01 01 24 90 01 01 81 3d 90 01 08 90 18 8b 90 01 01 24 90 01 01 8b 90 01 01 24 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Ranumbot_GL_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 90 01 01 24 90 01 01 89 90 01 01 24 90 01 01 8b 90 01 01 24 90 01 04 01 90 01 01 24 90 01 01 8b 90 01 01 24 90 01 01 8d 0c 37 33 c1 31 44 24 90 01 01 83 3d 90 01 05 c7 05 90 01 04 90 01 04 89 44 24 90 01 01 90 18 2b 5c 24 90 01 01 c7 44 24 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}