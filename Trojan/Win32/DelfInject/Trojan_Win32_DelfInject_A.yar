
rule Trojan_Win32_DelfInject_A{
	meta:
		description = "Trojan:Win32/DelfInject.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff } //02 00 
		$a_01_1 = {20 2f 31 73 74 65 6d 61 69 6c 2e 70 68 70 20 48 54 54 50 2f 31 2e 31 } //01 00   /1stemail.php HTTP/1.1
		$a_01_2 = {2e 31 36 32 2e 38 35 2e 32 33 34 } //01 00  .162.85.234
		$a_01_3 = {32 30 35 2e 32 35 31 2e 31 34 30 2e 31 37 38 } //00 00  205.251.140.178
	condition:
		any of ($a_*)
 
}