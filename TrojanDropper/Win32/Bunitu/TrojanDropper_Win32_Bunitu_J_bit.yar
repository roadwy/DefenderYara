
rule TrojanDropper_Win32_Bunitu_J_bit{
	meta:
		description = "TrojanDropper:Win32/Bunitu.J!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 2a 8b 45 90 01 01 89 85 90 01 04 8b 4d 90 01 01 03 8d 90 01 04 8b 55 90 01 01 03 95 90 01 04 8a 02 88 01 8b 4d 90 01 01 83 c1 01 89 4d 90 01 01 eb 90 00 } //1
		$a_03_1 = {8b 4d 08 8b 11 03 15 90 01 04 8b 45 08 89 10 90 00 } //1
		$a_03_2 = {8b d2 8b c9 8b d2 ba 90 01 04 8b d2 89 55 90 01 01 8b d2 83 45 90 01 02 83 45 90 01 02 83 6d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}