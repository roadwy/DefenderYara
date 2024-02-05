
rule PWS_Win32_Lineage_WL{
	meta:
		description = "PWS:Win32/Lineage.WL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e 18 2b fe 8b 4c 24 24 8a 14 37 51 52 8b cb e8 90 01 02 ff ff 88 06 46 4d 75 ea 5f 5e 5d 5b c2 14 00 90 00 } //01 00 
		$a_01_1 = {55 8b ec 8b 45 08 8b 4d 0c 25 ff 00 00 00 89 4d 0c 89 45 08 50 51 8b 45 08 8b 4d 0c d2 c8 89 45 08 59 58 8a 45 08 5d c2 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}