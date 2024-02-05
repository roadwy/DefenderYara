
rule Trojan_Win32_Stuxnet_A{
	meta:
		description = "Trojan:Win32/Stuxnet.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 37 6f 74 62 78 73 78 2e 64 6c 6c 00 } //01 00 
		$a_03_1 = {8b 74 24 08 80 7e 90 01 01 00 75 05 8d 46 90 01 01 5e c3 0f b7 46 90 01 01 57 50 8d 7e 90 01 01 57 e8 90 01 04 80 66 90 01 01 00 90 00 } //01 00 
		$a_01_2 = {ff 75 28 ff 75 24 ff 75 20 ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 51 38 5d c2 24 00 } //00 00 
	condition:
		any of ($a_*)
 
}