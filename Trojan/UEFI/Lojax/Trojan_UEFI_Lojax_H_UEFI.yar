
rule Trojan_UEFI_Lojax_H_UEFI{
	meta:
		description = "Trojan:UEFI/Lojax.H!UEFI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 b9 03 00 00 00 00 00 00 80 90 02 1f ff 90 01 01 08 90 02 2f ff 90 01 01 28 90 02 1f ff 90 01 01 10 90 00 } //01 00 
		$a_03_1 = {48 8b c1 0f b6 00 83 f8 61 0f 90 02 25 0f b6 40 01 85 c0 90 02 26 0f b6 40 02 83 f8 75 90 00 } //01 00 
		$a_03_2 = {45 33 c9 45 33 c0 33 d2 48 8b 90 01 03 48 8b 90 01 03 48 8b 90 01 02 48 8b 90 01 05 ff 90 90 08 01 00 00 90 00 } //01 00 
		$a_00_3 = {4d 9b 2d 83 d5 d8 5f 42 bd 52 5c 5a fb 2c 85 dc } //00 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}