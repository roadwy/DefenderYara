
rule Trojan_Win32_IcedID_MM_MTB{
	meta:
		description = "Trojan:Win32/IcedID.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 44 34 4c 0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8a 5d 00 8b 44 24 48 83 c4 90 01 01 8a 54 14 14 32 da 88 5d 00 45 48 89 44 24 10 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}