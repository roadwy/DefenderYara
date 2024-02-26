
rule Ransom_MSIL_Cryptolocker_AA_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 04 00 00 14 00 "
		
	strings :
		$a_81_0 = {53 4f 46 54 57 41 52 45 5c 4d 61 6c 77 61 72 65 62 79 74 65 73 5c 45 6b 61 74 69 5c } //01 00  SOFTWARE\Malwarebytes\Ekati\
		$a_81_1 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 } //01 00  /c vssadmin.exe delete shadows
		$a_81_2 = {2e 65 6e 63 72 79 70 74 65 64 } //01 00  .encrypted
		$a_81_3 = {45 6e 63 72 79 70 74 20 44 65 73 6b 74 6f 70 } //00 00  Encrypt Desktop
	condition:
		any of ($a_*)
 
}