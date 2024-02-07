
rule Trojan_BAT_LummaCStealer_CXFW_MTB{
	meta:
		description = "Trojan:BAT/LummaCStealer.CXFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 34 62 57 43 4f 66 45 74 53 30 4d 59 } //01 00  T4bWCOfEtS0MY
		$a_01_1 = {77 52 6d 57 43 4f 66 44 76 4b 63 63 6f } //01 00  wRmWCOfDvKcco
		$a_01_2 = {4b 5a 76 78 64 64 43 6e 69 68 34 73 62 57 78 36 68 61 6f } //01 00  KZvxddCnih4sbWx6hao
		$a_01_3 = {48 43 59 36 32 52 43 67 65 70 69 73 37 34 70 63 4e 58 34 } //01 00  HCY62RCgepis74pcNX4
		$a_01_4 = {51 4e 45 59 5a 6b 43 35 4a 78 44 47 6a 6c 72 41 59 77 53 } //00 00  QNEYZkC5JxDGjlrAYwS
	condition:
		any of ($a_*)
 
}