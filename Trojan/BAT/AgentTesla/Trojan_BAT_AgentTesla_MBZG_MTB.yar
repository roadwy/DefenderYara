
rule Trojan_BAT_AgentTesla_MBZG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 66 66 67 6a 66 64 73 64 64 66 73 64 67 6b 66 66 66 66 } //01 00  jffgjfdsddfsdgkffff
		$a_01_1 = {68 66 73 64 6b 66 66 64 67 68 73 66 64 66 66 64 61 66 64 63 68 64 } //01 00  hfsdkffdghsfdffdafdchd
		$a_01_2 = {66 67 68 68 64 66 67 66 66 66 66 64 66 64 66 64 64 73 68 66 64 61 73 64 66 68 } //01 00  fghhdfgffffdfdfddshfdasdfh
		$a_01_3 = {63 66 66 64 66 64 66 66 72 73 66 73 73 68 64 6b 66 66 66 67 68 } //01 00  cffdfdffrsfsshdkfffgh
		$a_01_4 = {68 6a 66 64 66 68 67 66 61 66 66 64 66 64 64 63 64 66 66 66 66 73 6b 68 6a } //01 00  hjfdfhgfaffdfddcdffffskhj
		$a_01_5 = {66 66 67 72 66 64 66 66 66 66 66 6b 68 73 6a 64 } //01 00  ffgrfdfffffkhsjd
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}