
rule Ransom_Win32_WannaCrypt_AT_MTB{
	meta:
		description = "Ransom:Win32/WannaCrypt.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 00 41 00 4e 00 41 00 43 00 52 00 59 00 21 00 } //01 00  WANACRY!
		$a_01_1 = {57 00 4e 00 63 00 72 00 79 00 40 00 32 00 6f 00 6c 00 37 00 } //01 00  WNcry@2ol7
		$a_01_2 = {69 00 63 00 61 00 63 00 6c 00 73 00 20 00 2e 00 20 00 2f 00 67 00 72 00 61 00 6e 00 74 00 20 00 45 00 76 00 65 00 72 00 79 00 6f 00 6e 00 65 00 3a 00 46 00 20 00 2f 00 54 00 20 00 2f 00 43 00 20 00 2f 00 51 00 } //01 00  icacls . /grant Everyone:F /T /C /Q
		$a_01_3 = {2e 00 77 00 6e 00 72 00 79 00 } //00 00  .wnry
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}