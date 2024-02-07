
rule Ransom_MSIL_Viper_MK_MTB{
	meta:
		description = "Ransom:MSIL/Viper.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {5b 52 61 6e 73 6f 6d 77 61 72 65 2e 56 69 70 65 72 2e 41 5d } //01 00  [Ransomware.Viper.A]
		$a_81_1 = {5c 56 69 70 65 72 5f 52 45 41 44 4d 45 2e 52 57 2d 53 4b 2e 74 78 74 } //01 00  \Viper_README.RW-SK.txt
		$a_81_2 = {59 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 56 69 70 65 72 20 52 61 6e 73 6f 6d 77 61 72 65 } //01 00  Your files were encrypted by Viper Ransomware
		$a_81_3 = {53 65 6e 64 20 24 35 30 30 20 69 6e 20 42 69 74 43 6f 69 6e 73 20 74 6f 20 74 68 69 73 20 61 64 64 72 65 73 73 3a } //00 00  Send $500 in BitCoins to this address:
		$a_00_4 = {5d 04 00 } //00 f0 
	condition:
		any of ($a_*)
 
}