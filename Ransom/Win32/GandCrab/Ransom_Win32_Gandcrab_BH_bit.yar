
rule Ransom_Win32_Gandcrab_BH_bit{
	meta:
		description = "Ransom:Win32/Gandcrab.BH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 85 c5 0a 00 a3 90 01 04 8b 0d 90 01 04 51 6a 00 ff 15 90 00 } //01 00 
		$a_03_1 = {73 54 8b 0d 90 01 04 03 8d 90 01 04 8b 15 90 01 04 03 95 90 01 04 8a 82 90 01 04 88 01 90 00 } //01 00 
		$a_03_2 = {88 08 8b 55 90 01 01 83 c2 01 89 55 90 09 09 00 8b 45 90 01 01 03 45 90 01 01 8a 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}