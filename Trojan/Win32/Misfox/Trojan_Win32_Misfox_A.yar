
rule Trojan_Win32_Misfox_A{
	meta:
		description = "Trojan:Win32/Misfox.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 c1 25 ff 00 00 00 8a 84 85 f4 fb ff ff 32 47 ff ff 8d e8 fb ff ff 88 44 3b ff 75 ae } //01 00 
		$a_01_1 = {47 45 54 00 2f 6c 61 73 74 2e 73 6f } //01 00 
		$a_01_2 = {5c 52 75 6e 00 00 00 47 6c 6f 62 61 6c 5c 5f 5f 64 65 63 6c 73 70 65 63 } //01 00 
		$a_01_3 = {47 6c 6f 62 61 6c 5c 6d 73 69 66 66 30 78 31 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}