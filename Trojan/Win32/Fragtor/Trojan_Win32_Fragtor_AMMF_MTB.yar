
rule Trojan_Win32_Fragtor_AMMF_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6f 77 66 61 77 6a 66 73 5f 6a 76 67 6a 67 66 6a 67 77 } //01 00  aowfawjfs_jvgjgfjgw
		$a_01_1 = {66 6b 61 77 6f 66 67 6a 77 67 6a 73 } //01 00  fkawofgjwgjs
		$a_01_2 = {73 64 68 64 75 65 44 76 69 75 65 65 } //01 00  sdhdueDviuee
		$a_01_3 = {78 63 76 6a 68 69 65 61 73 67 65 67 61 } //01 00  xcvjhieasgega
		$a_01_4 = {73 64 67 69 6f 65 61 73 67 6a 68 5f 61 6a 77 73 64 66 6a 73 61 64 5f 64 77 73 } //00 00  sdgioeasgjh_ajwsdfjsad_dws
	condition:
		any of ($a_*)
 
}