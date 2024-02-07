
rule Trojan_Win32_Dropper_AI_MTB{
	meta:
		description = "Trojan:Win32/Dropper.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {40 3b 45 e0 7e 02 33 c0 8a 94 05 a0 fe ff ff 30 94 0d 9c f2 ff ff 8d 8c 0d 9c f2 ff ff 8b 4d f8 41 3b 4d 08 89 4d f8 7c d7 } //01 00 
		$a_00_1 = {0f be 04 11 0f af c1 03 f0 41 3b cf 8d 74 46 05 7e ee } //01 00 
		$a_81_2 = {4d 65 61 64 6f 77 53 61 6c 61 63 69 74 79 } //01 00  MeadowSalacity
		$a_01_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00  GetTickCount
	condition:
		any of ($a_*)
 
}