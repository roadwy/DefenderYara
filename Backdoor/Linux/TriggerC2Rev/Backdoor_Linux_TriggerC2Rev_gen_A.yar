
rule Backdoor_Linux_TriggerC2Rev_gen_A{
	meta:
		description = "Backdoor:Linux/TriggerC2Rev.gen!A!!TriggerC2Rev.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_81_0 = {83 ee 01 89 45 84 89 f8 01 f0 0f af f8 83 e7 01 83 ff 00 0f 94 c6 83 fb 0a 0f 9c c0 88 f4 80 f4 ff 88 c3 80 f3 ff 80 f2 01 88 e7 80 e7 ff 20 d6 88 45 83 88 d8 24 ff 88 45 82 8a 45 83 20 d0 08 f7 8a 75 82 08 c6 30 f7 08 dc 80 f4 ff 80 ca 01 20 d4 08 e7 f6 c7 01 8b 75 84 0f 45 f1 8b 4d d0 89 31 } //03 00 
		$a_81_1 = {80 f2 00 88 fc 80 e4 00 20 d6 88 85 7b ff ff ff 24 00 20 d3 08 f4 08 d8 30 c4 8a 85 7b ff ff ff 08 c7 80 f7 ff 80 ca 00 20 d7 08 fc f6 c4 01 8b b5 7c ff ff ff 0f 45 f1 8b 4d d0 89 31 83 ec 0a 50 } //03 00 
		$a_81_2 = {83 ff 0a 41 0f 9c c2 45 88 cb 41 80 f3 ff 44 88 d3 80 f3 ff 80 f2 01 45 88 de 41 80 e6 ff 41 20 d1 41 88 df 41 80 e7 ff 41 20 d2 45 08 ce 45 08 d7 45 30 fe 41 08 db 41 80 f3 ff 80 ca 01 41 20 d3 45 08 de 41 f6 c6 01 0f 45 c1 4c 8b 65 b0 41 89 04 24 48 83 ec 0a 50 68 01 29 ac 46 } //03 00 
		$a_81_3 = {89 d7 81 c7 17 05 c0 15 83 ef 01 81 ef 17 05 c0 15 0f af d7 83 e2 01 83 fa 00 41 0f 94 c0 83 fe 0a 41 0f 9c c1 45 88 c2 45 20 ca 45 30 c8 45 08 c2 41 f6 c2 01 0f 45 c1 } //00 00 
	condition:
		any of ($a_*)
 
}