
rule Trojan_AndroidOS_SmsThief_O_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsThief.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 62 6c 35 73 } //01 00  com.example.bl5s
		$a_01_1 = {43 55 52 52 45 4e 54 4e 55 4d 42 45 52 } //01 00  CURRENTNUMBER
		$a_01_2 = {2f 62 6c 35 2f 6d 6f 62 2e 70 68 70 } //01 00  /bl5/mob.php
		$a_01_3 = {74 72 61 6e 73 66 65 72 4f 74 70 } //01 00  transferOtp
		$a_01_4 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //00 00  getMessageBody
	condition:
		any of ($a_*)
 
}