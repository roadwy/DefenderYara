
rule Trojan_Win64_AbuseCommMain_DB{
	meta:
		description = "Trojan:Win64/AbuseCommMain.DB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 00 6f 00 78 00 3a 00 35 00 42 00 38 00 35 00 46 00 30 00 46 00 35 00 32 00 46 00 39 00 38 00 39 00 43 00 34 00 32 00 46 00 45 00 31 00 38 00 41 00 30 00 38 00 33 00 35 00 31 00 44 00 34 00 42 00 39 00 46 00 35 00 30 00 44 00 37 00 41 00 39 00 38 00 33 00 32 00 44 00 42 00 45 00 34 00 41 00 30 00 36 00 38 00 33 00 34 00 36 00 44 00 45 00 33 00 35 00 44 00 35 00 43 00 46 00 38 00 46 00 34 00 31 00 30 00 } //01 00  tox:5B85F0F52F989C42FE18A08351D4B9F50D7A9832DBE4A068346DE35D5CF8F410
		$a_02_1 = {35 42 38 35 46 30 46 35 32 46 39 38 39 43 34 32 46 45 31 38 41 30 38 33 35 31 44 34 42 39 46 35 30 44 37 41 39 38 33 32 44 42 45 34 41 30 36 38 33 34 36 44 45 33 35 44 35 43 46 38 46 34 31 30 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00 90 00 } //01 00 
		$a_02_2 = {35 42 38 35 46 30 46 35 32 46 39 38 39 43 34 32 46 45 31 38 41 30 38 33 35 31 44 34 42 39 46 35 30 44 37 41 39 38 33 32 44 42 45 34 41 30 36 38 33 34 36 44 45 33 35 44 35 43 46 38 46 34 31 30 90 01 0c 4c 00 00 00 90 00 } //01 00 
		$a_00_3 = {5c 74 6f 78 5c 35 42 38 35 46 30 46 35 32 46 39 38 39 43 34 32 46 45 31 38 41 30 38 33 35 31 44 34 42 39 46 35 30 44 37 41 39 38 33 32 44 42 45 34 41 30 36 38 33 34 36 44 45 33 35 44 35 43 46 38 46 34 31 30 2e 68 73 74 72 } //00 00  \tox\5B85F0F52F989C42FE18A08351D4B9F50D7A9832DBE4A068346DE35D5CF8F410.hstr
	condition:
		any of ($a_*)
 
}