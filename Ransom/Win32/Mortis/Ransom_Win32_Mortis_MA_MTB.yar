
rule Ransom_Win32_Mortis_MA_MTB{
	meta:
		description = "Ransom:Win32/Mortis.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 4d 6f 72 74 69 73 4c 6f 63 6b 65 72 2e 70 64 62 } //01 00  \MortisLocker.pdb
		$a_01_1 = {5b 2a 5d 20 41 45 53 20 4b 65 79 3a } //00 00  [*] AES Key:
	condition:
		any of ($a_*)
 
}