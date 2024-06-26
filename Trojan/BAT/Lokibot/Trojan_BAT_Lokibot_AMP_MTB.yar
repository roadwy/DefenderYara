
rule Trojan_BAT_Lokibot_AMP_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.AMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 6e 30 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Rn0.Resources.resources
		$a_81_1 = {64 35 62 62 32 64 35 32 61 63 32 32 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  d5bb2d52ac22.Resources.resources
		$a_81_2 = {65 34 5a 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  e4Z.Resources.resources
		$a_81_3 = {48 65 6c 70 4b 65 79 77 6f 72 64 41 74 74 72 69 62 75 74 65 } //01 00  HelpKeywordAttribute
		$a_81_4 = {47 65 6e 65 72 61 74 65 64 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  GeneratedCodeAttribute
		$a_81_5 = {45 64 69 74 6f 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  EditorBrowsableAttribute
		$a_81_6 = {43 6f 6d 70 61 72 65 53 74 72 69 6e 67 } //01 00  CompareString
		$a_81_7 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_81_8 = {41 73 79 6e 63 43 61 6c 6c 62 61 63 6b } //00 00  AsyncCallback
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Lokibot_AMP_MTB_2{
	meta:
		description = "Trojan:BAT/Lokibot.AMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 64 6d 69 6e 41 70 70 2e 41 64 6d 69 6e 4c 6f 67 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //01 00  AdminApp.AdminLogin.resources
		$a_81_1 = {41 64 6d 69 6e 41 70 70 2e 41 64 6d 69 6e 50 61 6e 65 6c 2e 72 65 73 6f 75 72 63 65 73 } //01 00  AdminApp.AdminPanel.resources
		$a_81_2 = {41 64 6d 69 6e 41 70 70 2e 4d 6f 76 65 4f 75 74 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //01 00  AdminApp.MoveOutForm.resources
		$a_81_3 = {41 64 6d 69 6e 41 70 70 2e 50 72 65 76 69 6c 65 67 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00  AdminApp.Previlege.resources
		$a_81_4 = {41 64 6d 69 6e 41 70 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  AdminApp.Properties.Resources.resources
		$a_81_5 = {41 64 6d 69 6e 41 70 70 2e 52 65 63 65 69 70 74 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //01 00  AdminApp.ReceiptForm.resources
		$a_81_6 = {41 64 6d 69 6e 41 70 70 2e 52 65 67 52 65 63 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //01 00  AdminApp.RegRecForm.resources
		$a_81_7 = {41 64 6d 69 6e 41 70 70 2e 52 6f 6f 6d 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //01 00  AdminApp.RoomForm.resources
		$a_01_8 = {41 00 64 00 6d 00 69 00 6e 00 41 00 70 00 70 00 5c 00 62 00 69 00 6e 00 5c 00 44 00 65 00 62 00 75 00 67 00 } //01 00  AdminApp\bin\Debug
		$a_01_9 = {68 00 6f 00 74 00 65 00 6c 00 2e 00 62 00 69 00 6e 00 } //00 00  hotel.bin
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Lokibot_AMP_MTB_3{
	meta:
		description = "Trojan:BAT/Lokibot.AMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 13 00 00 01 00 "
		
	strings :
		$a_81_0 = {48 54 47 5f 53 6e 61 6b 65 2e 41 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.A.resources
		$a_81_1 = {48 54 47 5f 53 6e 61 6b 65 2e 42 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.B.resources
		$a_81_2 = {48 54 47 5f 53 6e 61 6b 65 2e 43 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.C.resources
		$a_81_3 = {48 54 47 5f 53 6e 61 6b 65 2e 66 72 6d 43 68 6f 6f 73 65 50 4e 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.frmChoosePN.resources
		$a_81_4 = {48 54 47 5f 53 6e 61 6b 65 2e 66 72 6d 42 75 79 41 43 61 72 64 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.frmBuyACard.resources
		$a_81_5 = {48 54 47 5f 53 6e 61 6b 65 2e 66 72 6d 42 69 67 43 61 72 64 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.frmBigCard.resources
		$a_81_6 = {48 54 47 5f 53 6e 61 6b 65 2e 66 72 6d 53 6e 61 6b 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.frmSnake.resources
		$a_81_7 = {48 54 47 5f 53 6e 61 6b 65 2e 66 72 6d 46 6f 72 74 75 6e 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.frmFortune.resources
		$a_81_8 = {48 54 47 5f 53 6e 61 6b 65 2e 62 61 73 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.base.resources
		$a_81_9 = {48 54 47 5f 53 6e 61 6b 65 2e 66 72 6d 46 61 74 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.frmFate.resources
		$a_81_10 = {48 54 47 5f 53 6e 61 6b 65 2e 48 69 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.Hi.resources
		$a_81_11 = {48 54 47 5f 53 6e 61 6b 65 2e 75 73 61 69 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.usai.resources
		$a_81_12 = {48 54 47 5f 53 6e 61 6b 65 2e 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.Main.resources
		$a_81_13 = {48 54 47 5f 53 6e 61 6b 65 2e 66 72 6d 43 68 6f 6f 73 65 41 76 61 74 61 72 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.frmChooseAvatar.resources
		$a_81_14 = {48 54 47 5f 53 6e 61 6b 65 2e 66 72 6d 57 69 6e 6e 65 72 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.frmWinner.resources
		$a_81_15 = {48 54 47 5f 53 6e 61 6b 65 2e 44 65 66 6f 72 6d 61 74 74 65 72 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.Deformatter.resources
		$a_81_16 = {48 54 47 5f 53 6e 61 6b 65 2e 48 69 53 6b 6f 72 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.HiSkor.resources
		$a_81_17 = {48 54 47 5f 53 6e 61 6b 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  HTG_Snake.Resources.resources
		$a_81_18 = {24 31 39 35 36 65 37 33 64 2d 37 33 39 32 2d 34 32 34 61 2d 61 37 35 35 2d 33 61 61 37 62 38 37 33 38 64 34 37 } //00 00  $1956e73d-7392-424a-a755-3aa7b8738d47
	condition:
		any of ($a_*)
 
}