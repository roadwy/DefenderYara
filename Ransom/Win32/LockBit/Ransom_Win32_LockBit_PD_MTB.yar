
rule Ransom_Win32_LockBit_PD_MTB{
	meta:
		description = "Ransom:Win32/LockBit.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f9 2b cf 0f b6 16 03 c2 46 03 d8 4f 75 f5 bf 90 01 04 81 f7 90 01 04 33 d2 f7 f7 52 8b c3 33 d2 f7 f7 8b da 58 85 c9 75 c5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}