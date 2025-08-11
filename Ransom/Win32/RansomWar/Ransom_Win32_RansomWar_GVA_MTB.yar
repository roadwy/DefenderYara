
rule Ransom_Win32_RansomWar_GVA_MTB{
	meta:
		description = "Ransom:Win32/RansomWar.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0c 00 00 "
		
	strings :
		$a_01_0 = {57 61 72 20 62 79 20 5b 57 61 72 47 61 6d 65 2c 23 65 6f 66 5d 20 28 20 2a 2a 2a 2a 20 74 69 20 61 6d 6f 20 61 6e 63 68 65 20 73 65 20 74 75 20 6e 6f 6e 20 6d 69 20 72 69 63 61 6d 62 69 20 29 } //1 War by [WarGame,#eof] ( **** ti amo anche se tu non mi ricambi )
		$a_01_1 = {44 65 61 72 20 75 73 65 72 2c } //1 Dear user,
		$a_01_2 = {59 6f 75 20 61 72 65 20 72 65 61 64 69 6e 67 20 74 68 65 20 6d 61 69 6c 21 } //1 You are reading the mail!
		$a_01_3 = {48 69 2c 20 79 6f 75 20 77 6f 6e 20 } //1 Hi, you won 
		$a_01_4 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 5c 35 2e 30 5c 4d 61 69 6c } //3 \Software\Microsoft\Outlook Express\5.0\Mail
		$a_01_5 = {57 61 72 6e 20 6f 6e 20 4d 61 70 69 20 53 65 6e 64 } //1 Warn on Mapi Send
		$a_01_6 = {4d 41 50 49 4c 6f 67 6f 6e } //1 MAPILogon
		$a_01_7 = {4d 41 50 49 46 69 6e 64 4e 65 78 74 } //1 MAPIFindNext
		$a_01_8 = {4d 41 50 49 52 65 61 64 4d 61 69 6c } //1 MAPIReadMail
		$a_01_9 = {4d 41 50 49 53 65 6e 64 4d 61 69 6c } //1 MAPISendMail
		$a_01_10 = {4d 41 50 49 4c 6f 67 6f 66 66 } //1 MAPILogoff
		$a_01_11 = {73 6f 6d 65 73 6f 6d 65 57 61 72 5f 45 4f 46 } //1 somesomeWar_EOF
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=14
 
}