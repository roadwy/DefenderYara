
rule Ransom_Win32_Cryakl_PAA_MTB{
	meta:
		description = "Ransom:Win32/Cryakl.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 73 73 68 6f 6c 65 } //01 00  asshole
		$a_01_1 = {52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //01 00  README.txt
		$a_01_2 = {68 65 6c 70 78 6d 37 32 2e 62 65 67 65 74 2e 74 65 63 68 } //01 00  helpxm72.beget.tech
		$a_01_3 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //00 00  software\microsoft\windows\currentversion\run
	condition:
		any of ($a_*)
 
}