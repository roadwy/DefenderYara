
rule Trojan_Win32_Lockbit_SRP_MTB{
	meta:
		description = "Trojan:Win32/Lockbit.SRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {a3 fc 19 58 00 c6 05 93 24 42 00 65 c6 05 89 24 42 00 69 c6 05 8c 24 42 00 75 c6 05 8e 24 42 00 6c c6 05 8d 24 42 00 61 c6 05 91 24 42 00 6f c6 05 95 24 42 00 74 c6 05 88 24 42 00 56 c6 05 94 24 42 00 63 c6 05 8f 24 42 00 50 c6 05 96 24 42 00 00 c6 05 8b 24 42 00 74 c6 05 92 24 42 00 74 c6 05 8a 24 42 00 72 c6 05 90 24 42 00 72 } //01 00 
		$a_01_1 = {73 65 6c 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}