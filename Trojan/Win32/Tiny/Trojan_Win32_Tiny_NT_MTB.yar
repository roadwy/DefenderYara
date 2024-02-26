
rule Trojan_Win32_Tiny_NT_MTB{
	meta:
		description = "Trojan:Win32/Tiny.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b d8 b8 08 00 00 00 e8 bf d9 ff ff 8b 15 90 01 04 89 10 89 58 04 a3 10 30 05 00 5b c3 90 00 } //01 00 
		$a_01_1 = {45 69 6e 20 53 79 73 74 65 6d 66 65 68 6c 65 72 20 69 73 74 20 61 75 66 67 65 74 72 65 74 65 } //00 00  Ein Systemfehler ist aufgetrete
	condition:
		any of ($a_*)
 
}