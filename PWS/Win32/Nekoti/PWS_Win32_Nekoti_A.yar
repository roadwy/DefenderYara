
rule PWS_Win32_Nekoti_A{
	meta:
		description = "PWS:Win32/Nekoti.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {ff 45 e8 eb 07 c7 45 e8 01 00 00 00 a1 c0 fe 4a 00 8b 55 e8 0f b6 5c 10 ff 33 5d ec 3b fb 7c 0a 81 c3 ff 00 00 00 } //01 00 
		$a_01_1 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00 
		$a_01_2 = {48 54 54 50 2f 31 2e 30 20 32 30 30 20 4f 4b } //00 00 
	condition:
		any of ($a_*)
 
}