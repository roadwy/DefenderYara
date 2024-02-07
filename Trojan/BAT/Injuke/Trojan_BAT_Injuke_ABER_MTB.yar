
rule Trojan_BAT_Injuke_ABER_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ABER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {2b 0a 2b 0b 18 2b 0b 1f 10 2b 0e 2a 03 2b f3 02 2b f2 6f 90 01 03 0a 2b ee 28 90 01 03 0a 2b eb 90 00 } //01 00 
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_3 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}