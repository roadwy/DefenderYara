
rule Trojan_WinNT_Tandfuy_A{
	meta:
		description = "Trojan:WinNT/Tandfuy.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 41 00 68 00 6e 00 46 00 6c 00 74 00 32 00 4b 00 2e 00 73 00 79 00 73 00 00 00 } //01 00 
		$a_00_1 = {00 00 6d 00 73 00 73 00 65 00 63 00 65 00 73 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_03_2 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8d 75 90 01 01 a5 a4 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}