
rule Ransom_MSIL_Cryptolocker_EL_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 10 00 00 32 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //32 00  All your files have been encrypted
		$a_81_1 = {45 78 69 73 74 69 6e 67 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 66 6f 75 6e 64 } //32 00  Existing encrypted files found
		$a_81_2 = {46 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //32 00  Files has been encrypted
		$a_81_3 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //14 00  All your important files are encrypted
		$a_81_4 = {70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //14 00  protonmail.com
		$a_81_5 = {52 61 6e 73 6f 6d 4d 65 73 73 61 67 65 } //14 00  RansomMessage
		$a_81_6 = {49 4d 50 4f 52 54 41 4e 54 20 52 45 41 44 20 4d 45 2e 68 74 6d 6c } //14 00  IMPORTANT READ ME.html
		$a_81_7 = {4c 65 67 69 6f 6e 4c 6f 63 6b 65 72 } //03 00  LegionLocker
		$a_81_8 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //03 00  vssadmin delete shadows /all /quiet
		$a_81_9 = {6d 69 6d 69 6b 61 74 7a 5f 74 72 75 6e 6b 2e 7a 69 70 } //03 00  mimikatz_trunk.zip
		$a_81_10 = {53 65 6e 64 20 6d 65 20 31 30 30 30 24 20 74 6f 20 74 68 69 73 20 62 69 74 63 6f 69 6e 20 61 64 64 72 65 73 73 } //03 00  Send me 1000$ to this bitcoin address
		$a_81_11 = {76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //01 00  vssadmin Delete Shadows /all /quiet
		$a_81_12 = {45 6e 63 79 70 74 65 64 4b 65 79 } //01 00  EncyptedKey
		$a_81_13 = {2e 65 6e 63 72 79 70 74 65 64 } //01 00  .encrypted
		$a_81_14 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //01 00  bytesToBeEncrypted
		$a_81_15 = {2e 4c 65 67 69 6f 6e } //00 00  .Legion
	condition:
		any of ($a_*)
 
}