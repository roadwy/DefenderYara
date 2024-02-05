
rule Ransom_Win32_RanzyLock_AA_MTB{
	meta:
		description = "Ransom:Win32/RanzyLock.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 52 00 41 00 4e 00 5a 00 59 00 4c 00 4f 00 43 00 4b 00 45 00 44 00 } //01 00 
		$a_01_1 = {34 34 36 35 36 43 36 35 37 34 36 35 32 30 35 33 36 38 36 31 36 34 36 46 37 37 37 33 32 30 32 46 34 31 36 43 36 43 32 30 32 46 35 31 37 35 36 39 36 35 37 34 } //01 00 
		$a_01_2 = {37 37 36 32 36 31 36 34 36 44 36 39 36 45 32 30 34 34 34 35 34 43 34 35 35 34 34 35 32 30 35 33 35 39 35 33 35 34 34 35 34 44 35 33 35 34 34 31 35 34 34 35 34 32 34 31 34 33 34 42 35 35 35 30 } //01 00 
		$a_01_3 = {77 00 69 00 70 00 65 00 5f 00 6d 00 65 00 } //01 00 
		$a_01_4 = {76 00 6d 00 69 00 63 00 6b 00 76 00 70 00 65 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}