
rule Trojan_AndroidOS_FakeInstSms_B{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 61 6e 6b 20 74 45 58 74 20 6e 6f 74 20 66 6f 75 6e 64 20 69 6e 20 70 6e 67 } //01 00  Chank tEXt not found in png
		$a_01_1 = {74 65 72 6d 61 74 65 2f 52 75 6c 65 41 63 74 69 76 69 74 79 } //01 00  termate/RuleActivity
		$a_01_2 = {72 65 67 5f 68 6f 73 74 } //01 00  reg_host
		$a_01_3 = {45 72 72 6f 72 20 73 65 6e 64 69 6e 67 20 73 6d 73 } //00 00  Error sending sms
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_FakeInstSms_B_2{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.B,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {e1 0d 0a 10 49 0e 13 11 b7 ed 8e dd 50 0d 13 11 28 f2 0d 0d 28 e8 49 0d 13 11 b7 ad 8e dd 50 0d 13 11 28 e9 e1 0d 09 10 49 0e 13 11 b7 ed 8e dd 50 0d 13 11 28 e0 49 0d 13 11 b7 9d 8e dd 50 0d 13 11 28 d9 e1 0d 08 10 49 0e 13 11 b7 ed 8e dd 50 0d 13 11 28 d0 } //01 00 
		$a_00_1 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 73 2f 75 70 64 61 74 65 2f 52 65 63 3b } //00 00  Lcom/androids/update/Rec;
	condition:
		any of ($a_*)
 
}