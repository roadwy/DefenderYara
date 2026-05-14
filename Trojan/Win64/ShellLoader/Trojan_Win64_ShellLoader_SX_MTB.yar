
rule Trojan_Win64_ShellLoader_SX_MTB{
	meta:
		description = "Trojan:Win64/ShellLoader.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {99 f7 fe 0f b6 cb 0f b6 44 15 d0 03 45 c8 03 c8 81 e1 ff 00 00 80 79 } //20
		$a_01_1 = {8b 03 8d 5b 04 03 45 e8 8d 52 02 89 01 8d 49 08 66 8b 42 fe 46 66 89 41 fc 8b 47 18 3b f0 72 e0 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}