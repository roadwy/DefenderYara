
rule Trojan_Win32_Smasarch_B{
	meta:
		description = "Trojan:Win32/Smasarch.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 68 61 72 65 77 61 72 65 2e 70 72 6f 2f 69 6e 64 65 78 66 72 2e 68 74 6d 6c 00 } //01 00 
		$a_01_1 = {73 6d 73 2f 69 73 76 61 6c 69 64 32 2e 70 68 70 3f 63 6f 64 65 3d } //01 00  sms/isvalid2.php?code=
		$a_01_2 = {65 6e 76 6f 79 65 72 20 75 6e 20 53 4d 53 20 61 76 65 63 20 6c 65 20 6d 6f 74 20 53 48 41 52 45 } //01 00  envoyer un SMS avec le mot SHARE
		$a_01_3 = {54 58 54 5f 4d 45 53 53 41 47 45 53 4f 4e 45 } //01 00  TXT_MESSAGESONE
		$a_01_4 = {43 68 61 71 75 65 20 53 4d 53 20 63 6f fb 74 65 20 31 2c 35 30 20 45 75 72 } //00 00 
	condition:
		any of ($a_*)
 
}