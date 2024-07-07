
rule Trojan_BAT_Tnega_AMP_MTB{
	meta:
		description = "Trojan:BAT/Tnega.AMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {58 00 6f 00 6c 00 61 00 2e 00 65 00 78 00 65 00 } //1 Xola.exe
		$a_01_1 = {43 00 4c 00 53 00 2e 00 64 00 6c 00 6c 00 } //1 CLS.dll
		$a_01_2 = {79 00 68 00 78 00 47 00 6b 00 4a 00 66 00 44 00 4d 00 70 00 54 00 66 00 69 00 55 00 6b 00 69 00 68 00 4f 00 79 00 77 00 4d 00 47 00 66 00 45 00 68 00 77 00 55 00 55 00 51 00 4c 00 4c 00 4d 00 6e 00 51 00 4f 00 73 00 45 00 42 00 76 00 70 00 6e 00 42 00 45 00 5a 00 55 00 6b 00 45 00 78 00 51 00 68 00 54 00 79 00 55 00 51 00 68 00 4a 00 77 00 6b 00 4d 00 4a 00 41 00 69 00 73 00 69 00 6b 00 54 00 } //1 yhxGkJfDMpTfiUkihOywMGfEhwUUQLLMnQOsEBvpnBEZUkExQhTyUQhJwkMJAisikT
		$a_81_3 = {53 65 63 75 72 69 74 79 50 65 72 6d 69 73 73 69 6f 6e 41 74 74 72 69 62 75 74 65 } //1 SecurityPermissionAttribute
		$a_81_4 = {53 48 41 32 35 36 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 SHA256CryptoServiceProvider
		$a_81_5 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_81_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_7 = {68 70 43 47 47 73 78 6e 42 66 6b 70 5a 79 54 43 } //1 hpCGGsxnBfkpZyTC
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule Trojan_BAT_Tnega_AMP_MTB_2{
	meta:
		description = "Trojan:BAT/Tnega.AMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_81_0 = {54 61 6e 6b 47 61 6d 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 TankGame.My.Resources
		$a_81_1 = {54 61 6e 6b 47 61 6d 65 2e 47 61 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //1 TankGame.Game.resources
		$a_81_2 = {54 61 6e 6b 47 61 6d 65 2e 4d 61 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 TankGame.MainForm.resources
		$a_81_3 = {54 61 6e 6b 47 61 6d 65 2e 53 74 61 72 74 55 70 2e 72 65 73 6f 75 72 63 65 73 } //1 TankGame.StartUp.resources
		$a_81_4 = {54 61 6e 6b 47 61 6d 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 TankGame.Resources.resources
		$a_81_5 = {54 61 6e 6b 47 61 6d 65 2e 4d 75 6c 74 69 70 6c 65 42 6c 6f 63 6b 73 2e 72 65 73 6f 75 72 63 65 73 } //1 TankGame.MultipleBlocks.resources
		$a_81_6 = {54 61 6e 6b 47 61 6d 65 2e 49 6e 47 61 6d 65 4f 70 74 69 6f 6e 73 2e 72 65 73 6f 75 72 63 65 73 } //1 TankGame.InGameOptions.resources
		$a_81_7 = {54 61 6e 6b 47 61 6d 65 2e 51 75 69 63 6b 53 74 61 72 74 2e 72 65 73 6f 75 72 63 65 73 } //1 TankGame.QuickStart.resources
		$a_81_8 = {24 42 35 38 37 41 41 44 32 2d 31 45 41 34 2d 34 31 36 46 2d 39 39 30 34 2d 42 44 38 44 34 41 46 33 41 30 37 32 } //1 $B587AAD2-1EA4-416F-9904-BD8D4AF3A072
		$a_01_9 = {46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 FromBase64String
		$a_01_10 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 56 00 42 00 53 00 61 00 6d 00 70 00 6c 00 65 00 73 00 5c 00 43 00 6f 00 6c 00 6c 00 61 00 70 00 73 00 65 00 5c 00 48 00 69 00 67 00 68 00 53 00 63 00 6f 00 72 00 65 00 73 00 } //1 Software\VBSamples\Collapse\HighScores
		$a_01_11 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 52 00 65 00 63 00 75 00 72 00 73 00 69 00 76 00 65 00 46 00 6f 00 72 00 6d 00 43 00 72 00 65 00 61 00 74 00 65 00 } //1 WinForms_RecursiveFormCreate
		$a_01_12 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 53 00 65 00 65 00 49 00 6e 00 6e 00 65 00 72 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 } //1 WinForms_SeeInnerException
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}