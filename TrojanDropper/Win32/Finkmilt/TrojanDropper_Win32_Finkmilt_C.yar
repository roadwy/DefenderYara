
rule TrojanDropper_Win32_Finkmilt_C{
	meta:
		description = "TrojanDropper:Win32/Finkmilt.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {fc 33 c0 6a ff 59 f2 ae 38 07 75 de } //01 00 
		$a_01_1 = {ff 4d 08 ff 75 08 e8 c1 ff ff ff c9 c2 04 00 } //01 00 
		$a_03_2 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 90 17 09 01 01 01 01 01 01 01 01 01 31 32 33 34 35 36 37 38 39 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}