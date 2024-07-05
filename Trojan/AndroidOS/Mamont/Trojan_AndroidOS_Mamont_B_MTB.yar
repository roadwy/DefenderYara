
rule Trojan_AndroidOS_Mamont_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Mamont.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 7a 7a 7a 2f 61 61 61 2f 63 6f 72 65 2f 53 6d 73 52 65 63 65 69 76 65 72 } //01 00  zzzz/aaa/core/SmsReceiver
		$a_01_1 = {63 6f 6d 2e 77 65 66 61 77 76 65 76 77 2e 61 70 70 } //01 00  com.wefawvevw.app
		$a_01_2 = {72 75 2e 79 6f 6f 2e 79 6f 6f 6d 6f 6e 65 } //00 00  ru.yoo.yoomone
	condition:
		any of ($a_*)
 
}