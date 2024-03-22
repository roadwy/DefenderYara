
rule Trojan_BAT_Taskun_EYAA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 11 10 91 11 0d 58 13 13 } //01 00 
		$a_01_1 = {11 0c 1f 16 5d 91 13 12 } //01 00 
		$a_01_2 = {44 42 43 6f 6e 6e 65 63 74 69 6f 6e 55 74 69 6c 69 74 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  DBConnectionUtility.Properties.Resources
	condition:
		any of ($a_*)
 
}