
rule Trojan_BAT_Tnega_SJK_MTB{
	meta:
		description = "Trojan:BAT/Tnega.SJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 70 6c 69 74 } //01 00  Split
		$a_81_1 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_2 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_81_3 = {43 61 65 73 61 72 45 6e 63 72 79 70 74 } //01 00  CaesarEncrypt
		$a_81_4 = {49 6e 69 74 69 61 6c 69 7a 65 43 6f 6d 70 6f 6e 65 6e 74 } //01 00  InitializeComponent
		$a_81_5 = {43 61 6c 6c 42 79 4e 61 6d 65 } //01 00  CallByName
		$a_81_6 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}