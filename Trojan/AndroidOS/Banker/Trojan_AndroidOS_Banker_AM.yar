
rule Trojan_AndroidOS_Banker_AM{
	meta:
		description = "Trojan:AndroidOS/Banker.AM,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {47 78 51 34 45 41 41 4f 45 7a 77 42 42 41 6b 50 41 52 55 3d } //01 00  GxQ4EAAOEzwBBAkPARU=
		$a_00_1 = {4f 77 45 4a 42 79 73 4f 43 68 63 45 42 68 4d 36 41 51 51 47 41 52 63 42 45 51 3d 3d } //01 00  OwEJBysOChcEBhM6AQQGARcBEQ==
		$a_00_2 = {42 41 55 4a 43 51 45 45 4f 78 41 49 46 67 3d 3d } //01 00  BAUJCQEEOxAIFg==
		$a_00_3 = {47 78 51 34 43 77 6b 53 4f 78 41 51 42 77 6f 42 45 44 67 57 47 67 30 3d } //01 00  GxQ4CwkSOxAQBwoBEDgWGg0=
		$a_00_4 = {47 77 45 4a 42 7a 73 4d 46 79 45 63 4d 67 49 4b 46 77 67 41 41 77 51 51 51 31 68 46 } //00 00  GwEJBzsMFyEcMgIKFwgAAwQQQ1hF
	condition:
		any of ($a_*)
 
}