
rule Ransom_MSIL_Cryptolocker_EK_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 0c 00 00 32 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 28 63 6f 75 6e 74 3a 20 6e 29 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //32 00  Your files (count: n) have been encrypted
		$a_81_1 = {4c 65 67 69 6f 6e 4c 6f 63 6b 65 72 34 } //32 00  LegionLocker4
		$a_03_2 = {4e 69 74 72 6f 52 61 6e 73 6f 6d 77 61 72 65 2e 90 02 05 2e 72 65 73 6f 75 72 63 65 73 90 00 } //14 00 
		$a_81_3 = {2e 46 61 6e 63 79 4c 65 61 6b 73 } //14 00  .FancyLeaks
		$a_81_4 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //14 00  bytesToBeEncrypted
		$a_81_5 = {44 69 73 63 6f 72 64 20 4e 69 74 72 6f } //03 00  Discord Nitro
		$a_81_6 = {46 61 6e 63 79 4c 6f 63 6b 65 72 } //03 00  FancyLocker
		$a_81_7 = {4c 65 67 69 6f 6e 4c 6f 63 6b 65 72 34 2e 5f 30 } //03 00  LegionLocker4._0
		$a_81_8 = {44 69 73 63 6f 72 64 20 46 72 65 65 20 4e 69 74 72 6f } //01 00  Discord Free Nitro
		$a_81_9 = {4e 6f 20 66 69 6c 65 73 20 74 6f 20 65 6e 63 72 79 70 74 } //01 00  No files to encrypt
		$a_81_10 = {70 61 73 73 77 6f 72 64 42 79 74 65 73 } //01 00  passwordBytes
		$a_81_11 = {43 6f 6e 66 75 73 65 72 45 78 } //00 00  ConfuserEx
	condition:
		any of ($a_*)
 
}