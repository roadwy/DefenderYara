
rule Trojan_Win32_Dudyeir_B{
	meta:
		description = "Trojan:Win32/Dudyeir.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 00 64 00 30 00 39 00 75 00 64 00 6e 00 00 00 } //01 00 
		$a_01_1 = {20 00 2d 00 6c 00 20 00 6e 00 6f 00 20 00 2d 00 6f 00 20 00 73 00 74 00 72 00 61 00 74 00 75 00 6d 00 2b 00 } //01 00   -l no -o stratum+
		$a_01_2 = {6e 00 73 00 64 00 69 00 75 00 79 00 65 00 69 00 72 00 2e 00 65 00 78 00 65 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}