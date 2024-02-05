
rule Trojan_Win32_Vicenor_gen_A{
	meta:
		description = "Trojan:Win32/Vicenor.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 61 72 6b 53 6f 6e 73 5f 63 72 79 70 74 } //01 00 
		$a_01_1 = {81 bd fc fb ff ff 10 27 00 00 75 07 6a 00 } //01 00 
		$a_01_2 = {8b 8d 4c fc ff ff 83 c1 08 6a 00 6a 04 8d 85 fc fe ff ff 50 51 } //00 00 
	condition:
		any of ($a_*)
 
}