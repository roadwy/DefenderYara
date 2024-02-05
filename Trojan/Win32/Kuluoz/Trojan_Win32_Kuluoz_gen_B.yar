
rule Trojan_Win32_Kuluoz_gen_B{
	meta:
		description = "Trojan:Win32/Kuluoz.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 70 68 70 3f 72 3d 67 61 74 65 2f 64 63 68 65 63 6b 00 } //01 00 
		$a_03_1 = {56 6a f1 50 ff 15 90 01 04 8b 0d 90 01 04 51 ff 15 90 01 04 8b 35 90 01 04 68 10 27 00 00 ff d6 eb f7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}