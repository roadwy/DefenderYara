
rule TrojanSpy_Win32_Banker_AOE{
	meta:
		description = "TrojanSpy:Win32/Banker.AOE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 70 6f 73 74 66 69 78 63 6f 6d 62 6f 2e 63 6f 6d } //01 00  .postfixcombo.com
		$a_01_1 = {39 35 39 36 36 44 38 45 39 32 36 36 41 39 42 42 38 41 44 35 36 37 43 36 38 37 43 41 38 45 } //01 00  95966D8E9266A9BB8AD567C687CA8E
		$a_01_2 = {33 36 46 45 30 44 31 43 46 31 30 35 31 41 32 39 45 46 30 36 30 41 } //01 00  36FE0D1CF1051A29EF060A
		$a_01_3 = {31 43 45 32 33 33 43 32 39 31 36 44 42 38 34 38 } //01 00  1CE233C2916DB848
		$a_01_4 = {eb 05 bf 01 00 00 00 8b 45 e4 33 db 8a 5c 38 ff 33 5d e0 3b 5d ec 7f 0b 81 c3 ff 00 00 00 2b 5d ec eb 03 } //00 00 
		$a_00_5 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}