
rule Trojan_BAT_Stealer_SM_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {24 32 64 66 62 35 62 65 61 2d 63 35 62 33 2d 34 36 33 39 2d 38 64 33 37 2d 62 36 31 34 39 64 36 36 35 65 63 61 } //02 00  $2dfb5bea-c5b3-4639-8d37-b6149d665eca
		$a_01_1 = {50 69 6c 6c 61 67 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 50 69 6c 6c 61 67 65 72 2e 70 64 62 } //02 00  Pillager\obj\Release\Pillager.pdb
		$a_01_2 = {50 69 6c 6c 61 67 65 72 2e 65 78 65 } //00 00  Pillager.exe
	condition:
		any of ($a_*)
 
}