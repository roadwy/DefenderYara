
rule Trojan_Win32_Ziconarch_A{
	meta:
		description = "Trojan:Win32/Ziconarch.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_11_0 = {6f 67 69 6e 63 6f 69 6e 2e 72 75 01 } //00 0d  杯湩潣湩爮ŵ
		$a_73_1 = {63 6f 6e 64 63 6f 69 6e 2e 72 75 01 00 10 11 5a 69 } //70 43 
		$a_69_2 = {5f 6f 72 69 67 69 6e 61 6c 01 00 1c 01 2f 7a 69 70 63 6f 69 6e 2e 72 75 2f 61 72 63 68 72 66 2f 3f 61 72 63 68 72 65 66 3d 01 00 2e 01 53 65 6e 64 69 6e 67 20 53 4d 53 20 79 6f 75 20 61 67 72 65 65 20 77 69 74 68 20 74 68 65 20 75 73 65 72 20 61 67 72 65 65 6d 65 6e 74 2e 00 00 5d 04 00 00 ca ff 02 80 5c 22 00 00 cb ff 02 80 00 00 } //01 00 
	condition:
		any of ($a_*)
 
}