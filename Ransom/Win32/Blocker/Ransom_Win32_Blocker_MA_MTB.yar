
rule Ransom_Win32_Blocker_MA_MTB{
	meta:
		description = "Ransom:Win32/Blocker.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {56 65 6c 39 41 51 41 41 58 34 76 76 36 4c 51 41 41 41 43 4c 2f 56 63 47 44 36 41 48 4a 71 45 77 } //05 00  Vel9AQAAX4vv6LQAAACL/VcGD6AHJqEw
		$a_01_1 = {41 4f 74 46 55 56 61 4c 64 54 79 4c 64 44 56 34 41 2f 56 57 69 33 59 67 41 2f 55 7a 79 55 6c 42 } //05 00  AOtFUVaLdTyLdDV4A/VWi3YgA/UzyUlB
		$a_01_2 = {41 46 46 56 41 38 31 52 36 41 45 41 41 41 44 44 69 30 51 6b 44 46 61 4c 64 43 51 4d 77 66 67 44 } //01 00  AFFVA81R6AEAAADDi0QkDFaLdCQMwfgD
		$a_01_3 = {43 72 79 70 74 43 72 65 61 74 65 48 61 73 68 } //01 00  CryptCreateHash
		$a_01_4 = {43 72 79 70 74 48 61 73 68 44 61 74 61 } //00 00  CryptHashData
	condition:
		any of ($a_*)
 
}