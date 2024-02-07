
rule TrojanSpy_AndroidOS_SmsThief_J_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 72 65 61 74 65 2e 70 68 70 } //01 00  create.php
		$a_00_1 = {64 65 6c 65 74 65 43 68 61 74 } //01 00  deleteChat
		$a_00_2 = {73 65 74 70 75 73 68 2e 70 68 70 } //01 00  setpush.php
		$a_00_3 = {6d 65 73 73 61 67 65 62 6f 74 2e 70 68 70 } //01 00  messagebot.php
		$a_00_4 = {68 74 74 70 73 3a 2f 2f 65 64 61 6c 61 74 2e 69 72 2d 34 36 35 34 39 2e 78 79 7a } //01 00  https://edalat.ir-46549.xyz
		$a_00_5 = {70 61 79 2e 70 68 70 3f 6e 61 6d 65 3d } //00 00  pay.php?name=
	condition:
		any of ($a_*)
 
}