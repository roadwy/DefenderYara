
rule Trojan_Win32_Injector_X{
	meta:
		description = "Trojan:Win32/Injector.X,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 72 37 71 65 74 37 71 36 77 74 65 37 31 32 37 36 72 38 } //01 00  tr7qet7q6wte71276r8
		$a_03_1 = {33 db 8d 0c 5d 90 01 04 91 2d 90 02 10 3b c2 75 90 01 01 8d 92 6f 8c ff ff eb 90 01 01 2b 15 90 01 04 3b c2 76 90 02 30 5d ff e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}