
rule Trojan_Win32_IcedId_PB_MTB{
	meta:
		description = "Trojan:Win32/IcedId.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 3b d8 7f 51 8b 07 8b 78 0c 8b 48 14 2b f9 8d 4d 90 01 01 51 ff d6 8b 4d 90 01 01 83 c3 05 8b 51 0c 2b 51 14 66 0f b6 04 10 66 99 66 f7 fb 8d 45 90 01 01 50 66 8b da ff d6 8a 0c 38 32 d9 8d 4d 90 01 01 51 ff d6 8b 4d 90 01 01 88 1c 38 8b 7d 08 b8 01 00 00 00 03 c8 89 4d 90 01 01 8b d9 eb 90 09 05 00 b8 90 01 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}