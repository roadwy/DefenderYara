
rule Trojan_Win32_Qbot_A_MTB{
	meta:
		description = "Trojan:Win32/Qbot.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 10 81 f2 cc 43 32 4f 83 c1 01 89 54 24 24 89 4c 24 1c 8b 54 24 18 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}