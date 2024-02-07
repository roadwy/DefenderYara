
rule Ransom_MSIL_Sapphire_DEA_MTB{
	meta:
		description = "Ransom:MSIL/Sapphire.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 61 70 70 68 69 72 65 20 52 61 6e 73 6f 6d 77 61 72 65 } //01 00  Sapphire Ransomware
		$a_81_1 = {5c 53 61 70 70 68 69 72 65 2d 52 61 6e 73 6f 6d 77 61 72 65 2d 6d 61 73 74 65 72 5c 53 61 70 70 68 69 72 65 20 52 61 6e 73 6f 6d 77 61 72 65 5c 6f 62 6a 5c 44 65 62 75 67 5c } //01 00  \Sapphire-Ransomware-master\Sapphire Ransomware\obj\Debug\
		$a_01_2 = {2e 00 56 00 49 00 56 00 45 00 4c 00 41 00 47 00 } //01 00  .VIVELAG
		$a_01_3 = {52 00 41 00 4e 00 53 00 4f 00 4d 00 57 00 41 00 52 00 45 00 20 00 23 00 4c 00 41 00 47 00 } //01 00  RANSOMWARE #LAG
		$a_01_4 = {30 00 35 00 32 00 32 00 35 00 30 00 30 00 35 00 38 00 32 00 30 00 35 00 30 00 37 00 35 00 30 00 32 00 35 00 30 00 37 00 35 00 32 00 30 00 37 00 38 00 32 00 30 00 } //00 00  052250058205075025075207820
	condition:
		any of ($a_*)
 
}