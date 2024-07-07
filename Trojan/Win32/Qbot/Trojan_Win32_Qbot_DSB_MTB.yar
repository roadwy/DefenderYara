
rule Trojan_Win32_Qbot_DSB_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DSB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 31 8a 6c 24 27 80 f5 e1 88 6c 24 4d 8b 74 24 1c 32 0c 16 66 8b 74 24 3e 8b 54 24 20 8b 5c 24 08 88 0c 1a } //1
		$a_01_1 = {8a 08 8b 44 24 20 89 44 24 50 8a 54 24 2b 8b 74 24 44 30 d1 31 ff 89 7c 24 50 8b 5c 24 4c 8b 44 24 18 88 0c 30 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}