
rule Trojan_BAT_DriveGraft_A_dha{
	meta:
		description = "Trojan:BAT/DriveGraft.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 65 6c 4d 61 69 6c } //1 delMail
		$a_01_1 = {67 65 74 43 6f 6d 6d 61 6e 64 46 72 6f 6d 44 72 61 66 74 } //1 getCommandFromDraft
		$a_01_2 = {63 72 65 61 74 65 45 6d 61 69 6c 44 72 61 66 74 } //1 createEmailDraft
		$a_01_3 = {75 70 6c 6f 61 64 78 41 73 79 6e 63 } //1 uploadxAsync
		$a_01_4 = {54 6f 6b 65 6e 69 6e 69 74 } //1 Tokeninit
		$a_01_5 = {4f 00 55 00 54 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 } //1 OUTCommandControl
		$a_01_6 = {2f 00 6d 00 65 00 2f 00 4d 00 61 00 69 00 6c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 2f 00 64 00 72 00 61 00 66 00 74 00 73 00 2f 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00 73 00 } //1 /me/MailFolders/drafts/messages
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=4
 
}