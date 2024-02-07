
rule Ransom_MSIL_DeathShadow_PA_MTB{
	meta:
		description = "Ransom:MSIL/DeathShadow.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {3c 45 6e 63 72 79 70 74 46 69 6c 65 3e 62 5f 5f 30 } //01 00  <EncryptFile>b__0
		$a_03_1 = {5c 44 65 61 74 68 5f 53 68 61 64 6f 77 5c 62 69 6e 5c 90 02 10 5c 53 65 63 75 72 65 64 5c 44 65 61 74 68 5f 53 68 61 64 6f 77 2e 70 64 62 90 00 } //01 00 
		$a_01_2 = {44 00 65 00 61 00 74 00 68 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 2e 00 65 00 78 00 65 00 } //01 00  Death_Shadow.exe
		$a_01_3 = {41 00 67 00 69 00 6c 00 65 00 44 00 6f 00 74 00 4e 00 65 00 74 00 52 00 54 00 36 00 34 00 } //00 00  AgileDotNetRT64
	condition:
		any of ($a_*)
 
}