
rule Trojan_Win32_marte_RDA_MTB{
	meta:
		description = "Trojan:Win32/marte.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 6f 69 64 61 6f 66 61 64 65 66 67 68 64 61 73 75 68 67 } //01 00  Qoidaofadefghdasuhg
		$a_01_1 = {56 6f 6b 64 61 73 66 6f 75 61 6f 69 66 68 64 61 73 } //01 00  Vokdasfouaoifhdas
		$a_01_2 = {74 69 6d 65 47 65 74 54 69 6d 65 } //00 00  timeGetTime
	condition:
		any of ($a_*)
 
}