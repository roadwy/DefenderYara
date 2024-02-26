
rule Trojan_Win32_Minix_NLA_MTB{
	meta:
		description = "Trojan:Win32/Minix.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {c7 44 0d 00 7c 33 a2 ee 81 44 0d 00 20 a2 eb 90 01 04 b5 8e 81 74 0d 00 3c ba 9e 90 01 04 81 74 0d 00 90 01 04 66 f7 c3 7f ca 66 39 d8 89 bd 90 00 } //01 00 
		$a_01_1 = {59 6d 2e 59 6a 51 41 32 65 } //00 00  Ym.YjQA2e
	condition:
		any of ($a_*)
 
}