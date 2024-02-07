
rule Trojan_BAT_Netwire_KJX_MTB{
	meta:
		description = "Trojan:BAT/Netwire.KJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 } //01 00  झझझझझझझझझ
		$a_01_1 = {34 00 1d 09 4d 00 1d 09 1d 09 75 00 1d 09 44 00 1d 09 } //01 00  4झMझझuझDझ
		$a_01_2 = {68 00 1d 09 47 00 30 00 1d 09 5a 00 51 00 1d 09 1d 09 1d 09 } //01 00  hझG0झZQझझझ
		$a_01_3 = {4d 00 51 00 1d 09 30 00 1d 09 1d 09 1d 09 1d 09 4b 00 67 00 } //01 00  MQझ0झझझझKg
		$a_01_4 = {67 00 1d 09 1d 09 1d 09 51 00 42 00 54 00 1d 09 48 00 51 00 1d 09 } //02 00  gझझझQBTझHQझ
		$a_81_5 = {47 65 74 54 79 70 65 } //02 00  GetType
		$a_81_6 = {52 65 70 6c 61 63 65 } //02 00  Replace
		$a_81_7 = {49 44 65 66 65 72 72 65 64 } //02 00  IDeferred
		$a_81_8 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //02 00  InvokeMember
		$a_81_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}