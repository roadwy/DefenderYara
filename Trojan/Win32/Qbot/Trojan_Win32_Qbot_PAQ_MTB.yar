
rule Trojan_Win32_Qbot_PAQ_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 5a 23 81 cf 1e fe 4d e7 d5 8f 2f 9d 29 ac 88 7b e9 8a } //01 00 
		$a_01_1 = {24 60 7f c8 81 4a bb 1f a9 94 c3 73 c2 76 c9 e5 0b 9d f3 } //01 00 
		$a_01_2 = {1b b9 7e 04 60 46 73 d0 ec c3 02 79 1a d4 95 86 97 b9 20 bc 88 09 3f 77 88 ec b9 e0 2e } //01 00 
		$a_01_3 = {48 c0 0d 70 05 2b 21 bf 83 b7 27 25 49 ad e6 d1 d8 ee 16 88 d4 64 4c 05 e9 c2 dc 98 4b } //00 00 
	condition:
		any of ($a_*)
 
}