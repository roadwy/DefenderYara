
rule Trojan_Win32_Spysnake_MAB_MTB{
	meta:
		description = "Trojan:Win32/Spysnake.MAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 f4 03 55 fc 0f b6 02 33 c1 8b 4d f4 03 4d fc 88 01 8b 55 fc 83 c2 01 89 55 fc eb c8 8d 45 e8 50 6a 40 8b 4d f8 51 8b 55 f4 52 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}