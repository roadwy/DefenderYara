
rule TrojanDropper_Win32_Figpuf_A{
	meta:
		description = "TrojanDropper:Win32/Figpuf.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 ec 01 00 00 00 33 ff ff 15 90 01 04 6a 1a 59 99 f7 f9 8b 4d 08 57 8d 72 61 ff 15 90 01 04 47 83 ff 0a 66 89 30 7c de 90 00 } //01 00 
		$a_01_1 = {80 39 3d 74 33 85 c0 75 04 8b c2 eb 02 03 c7 0f b6 00 } //01 00 
		$a_00_2 = {2c 00 72 00 75 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}