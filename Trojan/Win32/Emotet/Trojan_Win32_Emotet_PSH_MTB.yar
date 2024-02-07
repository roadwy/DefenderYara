
rule Trojan_Win32_Emotet_PSH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 44 34 90 01 01 0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 83 c4 90 01 01 83 c5 01 0f b6 54 14 90 01 01 30 55 90 00 } //01 00 
		$a_81_1 = {6c 65 62 67 53 64 33 45 52 46 49 6d 75 36 31 47 32 33 38 36 43 6d 46 64 4e 35 45 38 6e 5a 6c 6f 55 67 71 48 } //00 00  lebgSd3ERFImu61G2386CmFdN5E8nZloUgqH
	condition:
		any of ($a_*)
 
}