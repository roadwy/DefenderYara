
rule Trojan_Win32_Jaik_HNA_MTB{
	meta:
		description = "Trojan:Win32/Jaik.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 52 65 73 74 6f 72 65 50 72 69 76 69 6c 65 67 65 00 00 25 64 00 00 2e 74 6f 70 3a } //01 00 
		$a_01_1 = {73 74 72 52 65 6d 6f 76 65 53 70 65 63 43 68 61 72 20 70 61 72 61 6d 20 65 72 72 6f 72 0a 00 00 32 31 34 37 34 38 33 36 35 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}