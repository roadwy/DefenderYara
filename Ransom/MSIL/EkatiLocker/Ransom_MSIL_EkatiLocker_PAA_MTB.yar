
rule Ransom_MSIL_EkatiLocker_PAA_MTB{
	meta:
		description = "Ransom:MSIL/EkatiLocker.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 } //01 00  /c vssadmin.exe delete shadows
		$a_01_1 = {65 6b 61 74 69 2e 52 61 6e 73 6f 6d 4d 65 73 73 61 67 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ekati.RansomMessage.resources
		$a_01_2 = {42 6c 6f 63 6b 57 65 62 50 72 6f 74 65 63 74 69 6f 6e } //01 00  BlockWebProtection
		$a_01_3 = {46 00 69 00 6c 00 65 00 73 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //01 00  Files Encrypted
		$a_01_4 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  taskkill.exe
		$a_01_5 = {54 65 73 74 52 61 6e 73 6f 6d } //00 00  TestRansom
	condition:
		any of ($a_*)
 
}