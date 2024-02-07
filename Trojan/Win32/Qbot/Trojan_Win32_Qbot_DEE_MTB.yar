
rule Trojan_Win32_Qbot_DEE_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {50 4e 75 53 67 47 57 50 56 50 } //01 00  PNuSgGWPVP
		$a_81_1 = {4d 71 78 42 54 57 57 4d 42 66 } //01 00  MqxBTWWMBf
		$a_81_2 = {43 4a 48 73 53 4f 6d 56 41 67 } //01 00  CJHsSOmVAg
		$a_81_3 = {56 67 56 4b 50 6d 54 67 57 69 } //01 00  VgVKPmTgWi
		$a_81_4 = {4d 51 44 66 6f 5a 61 46 51 77 } //01 00  MQDfoZaFQw
		$a_81_5 = {63 48 64 43 76 4e 63 70 6f 6d } //01 00  cHdCvNcpom
		$a_81_6 = {4c 79 70 73 76 4d 44 6f 71 4e } //01 00  LypsvMDoqN
		$a_81_7 = {4c 78 4a 62 41 59 68 64 59 6f } //01 00  LxJbAYhdYo
		$a_81_8 = {53 62 48 62 53 54 76 4a 50 41 } //00 00  SbHbSTvJPA
	condition:
		any of ($a_*)
 
}