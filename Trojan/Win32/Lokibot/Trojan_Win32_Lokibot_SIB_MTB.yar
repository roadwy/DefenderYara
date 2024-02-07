
rule Trojan_Win32_Lokibot_SIB_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 00 76 00 6f 00 74 00 61 00 78 00 20 00 42 00 75 00 69 00 6c 00 64 00 65 00 72 00 } //01 00  Avotax Builder
		$a_03_1 = {5f 66 0f 66 c9 90 02 80 b8 90 01 04 90 02 b5 35 90 01 04 90 08 a0 02 05 90 01 04 90 08 aa 01 81 34 07 90 01 04 90 02 a5 83 c0 04 90 02 a5 3d 90 01 04 90 02 0a 90 18 0f 85 90 01 04 90 02 05 90 18 83 f0 00 90 02 5a ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}