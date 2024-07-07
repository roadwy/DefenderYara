
rule Trojan_Win32_Qakbot_SYS_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SYS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 15 98 10 55 00 8b 0d f8 4c 5b 00 0f b6 3d ef 4c 5b 00 8b 35 0c b2 74 00 8b c1 2b 05 f8 b1 74 00 8d 14 0f 2b 05 fc 4c 5b 00 8d 6c 32 ba 0f b6 15 e7 4c 5b 00 89 2d 00 4d 5b 00 be 02 00 00 00 0f b6 9e e4 4c 5b 00 03 dd 03 5c 24 14 8d 44 18 ba 3b c2 74 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}