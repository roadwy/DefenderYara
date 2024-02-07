
rule Trojan_Win32_Delf_EC_MTB{
	meta:
		description = "Trojan:Win32/Delf.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 06 00 "
		
	strings :
		$a_01_0 = {8b d6 b1 19 8b c7 48 85 c0 7c 07 40 30 0a 42 48 75 fa 5f 5e 5b c3 } //01 00 
		$a_01_1 = {46 41 44 47 52 51 53 50 43 55 54 57 56 69 68 6a } //00 00  FADGRQSPCUTWVihj
	condition:
		any of ($a_*)
 
}