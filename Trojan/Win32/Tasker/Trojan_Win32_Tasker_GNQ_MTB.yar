
rule Trojan_Win32_Tasker_GNQ_MTB{
	meta:
		description = "Trojan:Win32/Tasker.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 c0 90 01 01 89 45 fc 8b 4d fc 3b 4d 0c 7d 90 01 05 e8 90 01 04 55 fc 0f b6 02 83 f0 1e 8b 4d 08 03 4d fc 88 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}