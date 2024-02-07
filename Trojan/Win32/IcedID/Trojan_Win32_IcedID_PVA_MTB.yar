
rule Trojan_Win32_IcedID_PVA_MTB{
	meta:
		description = "Trojan:Win32/IcedID.PVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 04 38 88 04 3e 8b 75 fc 0f b6 c0 03 c2 0f b6 c0 88 0c 3e 8b 4d 08 8a 04 38 32 04 0b 88 01 } //01 00 
		$a_81_1 = {71 78 6e 56 58 35 59 52 6f 6e 69 61 35 4c 49 6b 6e 6b 4c 51 55 63 66 4c 4f 38 4e 59 76 6b 63 78 31 6d 6f 34 6e 73 31 56 48 30 79 } //00 00  qxnVX5YRonia5LIknkLQUcfLO8NYvkcx1mo4ns1VH0y
	condition:
		any of ($a_*)
 
}