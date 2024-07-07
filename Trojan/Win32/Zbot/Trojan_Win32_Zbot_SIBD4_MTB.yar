
rule Trojan_Win32_Zbot_SIBD4_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBD4!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b de 8b d2 81 e9 90 01 04 2b d9 ba 90 01 04 bb 90 01 04 bf 90 01 04 76 90 01 01 33 d9 31 3a 09 fb 03 dd 8b 32 7f 90 01 01 09 f3 8a d8 b0 90 01 01 8a c3 83 c6 90 01 01 89 32 5b 83 ec 90 01 01 83 c2 90 01 01 8b da 8b d9 8b cb 83 e9 90 01 01 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}