
rule Ransom_MSIL_CobraLocker_DD_MTB{
	meta:
		description = "Ransom:MSIL/CobraLocker.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 61 62 61 59 61 67 61 } //01 00  BabaYaga
		$a_81_1 = {41 45 53 5f 45 6e 63 72 79 70 74 } //01 00  AES_Encrypt
		$a_81_2 = {64 65 6c 5f 64 65 73 6b 74 6f 70 } //01 00  del_desktop
		$a_81_3 = {2e 6c 6f 63 6b 65 64 } //01 00  .locked
		$a_81_4 = {53 74 61 72 74 5f 45 6e 63 72 79 70 74 } //00 00  Start_Encrypt
	condition:
		any of ($a_*)
 
}