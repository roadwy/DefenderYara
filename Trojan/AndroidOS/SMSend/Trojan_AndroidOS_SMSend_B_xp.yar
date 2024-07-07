
rule Trojan_AndroidOS_SMSend_B_xp{
	meta:
		description = "Trojan:AndroidOS/SMSend.B!xp,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 23 74 70 3a 23 2f 23 2f 6d 70 62 23 63 63 2e 77 69 6e 2f 23 69 30 30 } //1 ht#tp:#/#/mpb#cc.win/#i00
		$a_00_1 = {63 72 65 61 74 65 53 63 61 6e 6e 65 72 } //1 createScanner
		$a_00_2 = {23 53 4d 23 53 5f 53 23 45 4e 54 } //1 #SM#S_S#ENT
		$a_00_3 = {75 70 64 23 61 23 74 65 20 64 23 74 20 73 65 74 20 66 23 6c 67 65 74 23 3d 31 20 77 23 68 65 72 65 20 73 6d 23 73 20 69 23 23 23 6e } //1 upd#a#te d#t set f#lget#=1 w#here sm#s i###n
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}