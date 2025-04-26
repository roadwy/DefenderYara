
rule Trojan_Win32_Qbot_DEI_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DEI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 5c 8b 4c 24 24 8a 14 01 8a 74 24 3f 8b 44 24 1c 89 44 24 74 30 f2 8b 74 24 50 66 c7 44 24 66 71 cf 8b 7c 24 2c 88 14 37 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}