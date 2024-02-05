
rule Ransom_Win32_WastedLocker_MA_MTB{
	meta:
		description = "Ransom:Win32/WastedLocker.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 d5 11 00 00 85 c0 74 48 c7 45 e4 90 01 04 8b 4d f8 3b 0d 90 01 04 90 13 68 90 01 04 6a 00 ff 15 90 01 04 03 45 f8 8b 55 f4 0f be 04 02 89 45 e4 8b 4d f8 03 4d f0 8b 55 fc 8a 45 e4 88 04 0a 8b 4d f8 83 c1 01 89 4d f8 eb af 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}