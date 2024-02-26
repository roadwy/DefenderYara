
rule Trojan_Win32_AsyncRAT_D_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 34 39 f7 e9 03 d1 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 c2 0f be c0 6b c0 90 01 01 2a c8 80 c1 90 01 01 30 0e 8b 4d 90 00 } //01 00 
		$a_01_1 = {50 72 6f 63 65 73 73 6f 72 4e 61 6d 65 53 74 72 69 6e 67 } //00 00  ProcessorNameString
	condition:
		any of ($a_*)
 
}