
rule Trojan_Win32_Gozi_RJ_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 d0 b9 30 00 00 00 99 f7 f9 8b 45 f8 8a 14 10 8b 4d d8 8b 45 d0 32 14 01 8b 4d d0 8b 45 fc 88 14 08 ff 45 d0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_RJ_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 55 10 33 d2 f7 75 f8 8b 4e 0c 8b 5e 04 03 cf 89 55 ec 85 c0 74 15 8b 39 8b 55 10 83 45 10 04 2b fb 03 df 83 c1 04 48 89 3a 75 eb } //00 00 
	condition:
		any of ($a_*)
 
}