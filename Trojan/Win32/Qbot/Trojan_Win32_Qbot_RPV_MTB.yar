
rule Trojan_Win32_Qbot_RPV_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 54 24 10 8d 42 04 02 05 90 01 04 8b 3d 90 01 04 8d 8e 90 01 04 89 4d 00 83 c5 04 89 0d 90 01 04 b1 a7 2a ca 2a 0d 90 01 04 02 c1 83 6c 24 18 01 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RPV_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RPV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a1 00 0f 47 00 8b 15 b0 0e 47 00 01 02 a1 e8 0e 47 00 2d a2 d1 00 00 03 05 00 0f 47 00 a3 f0 0e 47 00 a1 f0 0e 47 00 a3 ec 0e 47 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}