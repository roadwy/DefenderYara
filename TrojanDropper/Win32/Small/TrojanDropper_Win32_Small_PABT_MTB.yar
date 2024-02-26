
rule TrojanDropper_Win32_Small_PABT_MTB{
	meta:
		description = "TrojanDropper:Win32/Small.PABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 03 45 fc 0f b6 08 83 f1 18 8b 55 08 03 55 fc 88 0a 8b 45 0c 83 e8 01 89 45 0c 8b 4d fc 83 c1 01 89 4d fc 83 7d 0c 00 75 d4 } //01 00 
		$a_01_1 = {8b 55 08 03 55 fc 0f be 02 33 45 0c 8b 4d f4 03 4d fc 88 01 8b 55 fc 83 c2 01 89 55 fc 8b 45 f0 89 45 ec 8b 4d f0 83 e9 01 89 4d f0 83 7d ec 00 75 ce } //00 00 
	condition:
		any of ($a_*)
 
}