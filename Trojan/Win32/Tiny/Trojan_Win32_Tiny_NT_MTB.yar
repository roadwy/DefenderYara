
rule Trojan_Win32_Tiny_NT_MTB{
	meta:
		description = "Trojan:Win32/Tiny.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d8 b8 08 00 00 00 e8 bf d9 ff ff 8b 15 ?? ?? ?? ?? 89 10 89 58 04 a3 10 30 05 00 5b c3 } //5
		$a_01_1 = {45 69 6e 20 53 79 73 74 65 6d 66 65 68 6c 65 72 20 69 73 74 20 61 75 66 67 65 74 72 65 74 65 } //1 Ein Systemfehler ist aufgetrete
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}