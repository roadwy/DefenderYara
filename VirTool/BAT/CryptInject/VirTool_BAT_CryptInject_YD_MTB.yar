
rule VirTool_BAT_CryptInject_YD_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.YD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 1f 1f 5f 1f 18 62 7e 69 00 00 04 08 25 17 58 0c 91 1f 10 62 58 7e 69 00 00 04 08 25 17 58 0c 91 1e 62 58 7e 69 00 00 04 08 25 17 58 0c 91 58 0b } //01 00 
		$a_01_1 = {16 0b 02 0c 7e 69 00 00 04 08 25 17 58 0c 91 0d 09 20 80 00 00 00 5f 3a 14 00 00 00 } //01 00 
		$a_01_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //00 00 
	condition:
		any of ($a_*)
 
}