
rule Trojan_Win32_Delf_II{
	meta:
		description = "Trojan:Win32/Delf.II,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {37 33 32 32 2e 63 6f 6d } //01 00 
		$a_01_1 = {6d 79 31 31 35 2e 6e 65 74 } //02 00 
		$a_01_2 = {44 65 6c 54 65 6d 70 2e 62 61 74 00 ff ff ff ff 05 00 00 00 3a 52 64 65 6c 00 00 00 ff ff ff ff 04 00 00 00 64 65 6c 20 00 00 00 00 ff ff ff ff 09 00 00 00 69 66 20 65 78 69 73 74 20 } //02 00 
		$a_01_3 = {20 67 6f 74 6f 20 52 64 65 6c 00 00 ff ff ff ff 0f 00 00 00 64 65 6c 20 44 65 6c 54 65 6d 70 2e 62 61 74 } //02 00 
		$a_01_4 = {e5 db d3 ce e4 af c0 c0 c6 f7 2e 6c 6e 6b 00 00 ff ff ff ff 09 00 00 00 33 36 30 73 65 2e 65 78 65 00 00 00 ff ff ff ff 07 00 00 00 61 62 63 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}