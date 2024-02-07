
rule Ransom_MSIL_Cryptolocker_DW_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 0c 00 00 32 00 "
		
	strings :
		$a_81_0 = {2e 6d 61 74 72 79 6f 73 68 6b 61 } //32 00  .matryoshka
		$a_81_1 = {2e 42 61 70 68 6f 6d 65 74 } //32 00  .Baphomet
		$a_81_2 = {68 61 6e 74 61 5f 32 5f 30 } //14 00  hanta_2_0
		$a_81_3 = {4e 69 74 72 6f 53 6e 79 70 61 } //14 00  NitroSnypa
		$a_81_4 = {62 61 70 68 6f 2e 6a 70 67 } //14 00  bapho.jpg
		$a_81_5 = {68 61 6e 74 61 5f 72 61 6e 73 6f 6d } //03 00  hanta_ransom
		$a_81_6 = {44 69 73 63 6f 72 64 20 4e 69 74 72 6f 20 53 6e 69 70 65 72 } //03 00  Discord Nitro Sniper
		$a_81_7 = {79 6f 75 72 6b 65 79 2e 6b 65 79 } //03 00  yourkey.key
		$a_81_8 = {68 6f 77 5f 74 6f 5f 72 65 63 6f 76 65 72 } //01 00  how_to_recover
		$a_81_9 = {62 74 6e 5f 43 6f 70 79 57 61 6c 6c 65 74 } //01 00  btn_CopyWallet
		$a_81_10 = {69 70 69 6e 66 6f 2e 69 6f } //01 00  ipinfo.io
		$a_81_11 = {73 74 61 72 74 20 65 6e 63 72 79 70 72 69 6f 6e } //00 00  start encryprion
	condition:
		any of ($a_*)
 
}