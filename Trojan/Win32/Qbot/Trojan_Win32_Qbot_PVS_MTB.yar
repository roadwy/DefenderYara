
rule Trojan_Win32_Qbot_PVS_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PVS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 0f 8b 4c 24 20 8b 74 24 04 32 1c 31 8b 4c 24 1c 88 1c 31 } //2
		$a_01_1 = {8a 1c 06 8b 44 24 30 32 1c 08 8b 44 24 2c 88 1c 08 } //2
		$a_01_2 = {8b 44 24 28 83 c0 01 8a 4c 24 07 80 f1 ff 88 4c 24 3f } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=2
 
}