
rule Ransom_Win32_Locky_GJW_MTB{
	meta:
		description = "Ransom:Win32/Locky.GJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {50 58 03 c1 54 8f 45 c4 32 d2 02 55 d4 56 8f 45 c0 89 45 e8 8b 7d e8 8b ff 8b 45 d8 33 45 dc 33 c2 f7 d0 8a ff 0a 05 90 01 04 88 07 8b c6 69 c0 90 01 04 01 05 90 01 04 8b ce 90 00 } //01 00 
		$a_80_1 = {42 61 63 6b 75 70 2e 6f 63 78 } //Backup.ocx  00 00 
	condition:
		any of ($a_*)
 
}