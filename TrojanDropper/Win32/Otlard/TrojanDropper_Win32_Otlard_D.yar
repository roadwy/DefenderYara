
rule TrojanDropper_Win32_Otlard_D{
	meta:
		description = "TrojanDropper:Win32/Otlard.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {32 45 ff bb 90 01 04 88 84 0d 90 01 02 ff ff 8b c6 99 f7 fb 41 8a c2 b2 03 f6 ea 00 45 ff 90 00 } //01 00 
		$a_01_1 = {c1 c2 03 32 10 40 80 38 00 } //01 00 
		$a_01_2 = {0f 31 69 d0 05 84 08 08 42 0b c1 b8 ff ff 00 00 f7 e2 } //00 00 
	condition:
		any of ($a_*)
 
}