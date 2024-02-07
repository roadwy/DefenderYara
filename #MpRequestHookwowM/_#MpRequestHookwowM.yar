
rule _#MpRequestHookwowM{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 0a 5b f7 fb 8a 82 90 01 04 30 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_2{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {87 ef 5f 83 ff 04 7c 90 01 01 31 6c 16 01 90 09 05 00 bf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_3{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 33 c8 8b 45 90 01 01 03 45 90 01 01 88 88 90 01 03 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_4{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 10 8a 4d 13 32 d1 02 d1 88 10 } //01 00 
		$a_01_1 = {55 03 c5 ff d0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_5{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 0c 17 8d 52 01 80 f1 8b 80 c1 5a 80 f1 11 80 e9 15 88 4a ff 4e 75 e8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_6{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 6e 5c 24 90 02 20 0f ef d9 90 02 20 0f 7e d8 90 02 20 83 f8 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_7{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {be 40 00 00 00 56 b9 00 30 00 00 51 68 90 01 04 6a 00 ff d0 50 8f 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_8{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 08 90 02 20 85 06 74 90 02 20 8b 44 24 0c 90 02 20 39 46 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_9{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 8b c2 85 c0 0f 84 90 01 04 58 52 ac 51 8a c8 30 0f 59 5a 47 4a 49 75 e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_10{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 e7 01 f2 01 f2 89 94 24 90 01 04 89 84 24 90 01 04 8b 44 24 08 88 1c 08 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_11{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 6e 5c 24 0c 90 02 20 0f ef d9 90 02 20 0f 7e d9 90 02 20 81 f9 00 00 04 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_12{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f9 00 0f 85 90 02 30 41 90 02 30 8b 43 2c 90 02 30 31 c8 90 02 30 83 f8 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_13{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {85 c9 7c 0f 8b c1 99 6a 90 01 01 5b f7 fb 8a 44 15 90 01 01 30 04 39 41 3b ce 72 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_14{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 8a 91 90 01 04 80 f2 ba 88 10 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_15{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 45 08 5a 30 02 } //01 00 
		$a_03_1 = {50 68 a7 00 00 00 ff 15 90 01 05 ff 06 81 3e 8b 5d 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_16{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 cc 93 ff d3 } //01 00 
		$a_03_1 = {0f b6 02 03 45 90 01 01 8b 0d 90 01 04 03 8d 90 01 04 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_17{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d9 03 d8 c6 03 68 41 4a 75 f3 } //01 00 
		$a_01_1 = {8d 0c 30 8a 09 80 f1 3c 8d 1c 30 88 0b 40 4a 75 ef } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_18{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 0c 30 8a 09 80 f1 cc 8d 1c 30 88 0b } //01 00 
		$a_03_1 = {8d 45 f8 50 6a 40 68 90 01 04 53 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_19{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f9 14 75 04 33 c9 eb 01 41 42 3b d6 72 e5 8b 45 b8 ff d0 90 09 0c 00 8a 81 90 01 04 30 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_20{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 5e f7 f6 8a 44 15 90 01 01 30 81 90 01 04 41 81 f9 90 01 04 72 e4 90 09 04 00 33 d2 6a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_21{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 f8 88 04 32 90 09 06 00 2a 05 90 01 03 00 90 00 } //01 00 
		$a_01_1 = {6a 40 68 00 30 00 00 53 6a 00 e8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_22{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 0c 30 8a 09 90 02 10 80 f1 75 8d 1c 30 88 0b 90 00 } //01 00 
		$a_01_1 = {8b cb 03 c8 c6 01 f0 43 4a 75 f5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_23{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 05 45 29 00 00 73 05 } //01 00 
		$a_01_1 = {33 c0 89 45 fc 8b 75 08 eb 05 80 33 08 eb 07 8b 5d fc 01 f3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_24{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {29 db 2b 1e f7 db f8 83 d6 04 f7 db 8d 5b f1 c1 cb 09 d1 c3 31 d3 4b 89 da c1 c2 09 d1 ca f7 da 53 8f 07 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_25{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 d2 74 15 52 ac 30 07 47 5a 4a e2 f3 } //01 00 
		$a_01_1 = {8b d4 b8 32 7c 40 00 41 89 15 2a 61 43 00 03 c1 ff d0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_26{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 1c b2 8b 05 90 01 04 01 c3 89 1c b2 81 c6 90 01 04 2b 3d 90 01 04 81 ee 90 01 04 81 fe 90 01 04 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_27{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 19 80 f3 7d 88 19 } //01 00 
		$a_03_1 = {8d 45 f0 50 6a 40 68 90 01 04 8b 45 90 01 01 50 ff 55 90 01 01 33 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_28{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 08 91 1f 1e 61 d2 9c 7e 90 01 01 00 00 90 01 01 17 58 90 00 } //01 00 
		$a_01_1 = {1f 44 0d 08 2d 27 09 1f 64 2f 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_29{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 94 05 90 01 04 33 ca 8b 45 f0 90 01 0e 8b 55 e8 88 0c 02 90 00 } //01 00 
		$a_01_1 = {8b 55 e8 83 c2 28 ff d2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_30{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 75 fc 03 75 f8 90 01 02 80 36 4a ff 45 fc 81 7d fc 90 01 04 75 90 00 } //01 00 
		$a_01_1 = {81 c3 50 28 00 00 89 1d } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_31{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 0c 07 e8 90 01 04 47 3b fe 90 00 } //01 00 
		$a_03_1 = {69 c0 fd 43 03 00 05 90 01 04 a3 90 01 04 c1 e8 10 30 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_32{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 48 fb 30 4c 05 90 01 01 40 83 f8 0c 90 00 } //01 00 
		$a_03_1 = {8d 34 08 8d 50 fb 40 30 16 83 f8 90 01 01 72 f2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_33{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 83 c4 08 8b d1 8a 12 80 f2 3a 88 10 ff 06 41 81 3e 98 5d 00 00 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_34{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 dd 80 f5 19 88 ac 24 90 01 04 89 54 24 90 01 01 8a 00 8b 54 24 90 01 01 8d 72 01 89 74 24 90 01 01 88 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_35{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10 } //01 00 
		$a_01_1 = {8b 4d 0c 01 0c 18 8b 42 04 47 83 e8 08 83 c6 02 d1 e8 3b f8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_36{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 04 33 c9 eb 01 41 40 3b c6 72 e5 8b 45 90 01 01 ff d0 90 09 0f 00 8a 91 90 01 04 30 90 90 90 01 04 83 f9 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_37{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {76 db ff 15 90 09 23 00 ad c1 c0 90 01 01 2b 05 90 01 04 33 05 90 01 04 03 05 90 01 04 33 05 90 01 04 ab 81 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_38{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 04 37 83 ee 01 79 f3 } //01 00 
		$a_03_1 = {33 d2 8b c6 f7 75 0c 8b 45 08 0f be 0c 02 0f b6 86 90 01 04 03 c7 03 c1 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_39{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 52 50 8b 06 99 03 04 24 13 54 24 90 01 01 83 c4 08 8b d1 8a 12 80 f2 0b 88 10 ff 06 41 81 3e 90 01 04 75 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_40{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {40 00 0f af 45 90 01 01 a3 90 01 02 40 00 8b 45 90 01 01 40 89 45 90 01 01 8b 45 90 01 01 05 90 01 02 00 00 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_41{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 03 89 45 90 01 01 8b 45 90 01 01 8b 55 90 01 01 eb 05 80 30 90 01 01 eb 04 01 d0 eb f7 ff 03 81 3b 90 01 04 75 e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_42{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c8 b8 01 00 00 00 99 f7 f9 33 f2 90 01 0c 8b 15 90 01 04 89 34 82 c7 45 90 01 05 a1 90 01 04 25 00 00 00 80 79 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_43{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 00 34 fb 83 ea 0d 73 05 e8 90 01 04 88 02 90 00 } //01 00 
		$a_03_1 = {81 c3 bf 03 00 00 73 05 e8 90 01 04 89 5d fc ff 65 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_44{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 67 66 66 66 f7 6c 24 90 01 01 d1 fa 8b c2 c1 e8 1f 03 c2 8b d8 0f af 90 01 01 24 90 01 01 0f af 5d 10 8a c3 32 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_45{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c8 8b 06 8b fb 8a 11 4f 88 10 40 41 85 ff } //01 00 
		$a_01_1 = {8b c8 c1 f9 03 8d 34 39 8b c8 83 e1 07 d2 e2 08 16 40 83 f8 40 7c e3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_46{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c3 8a 00 90 01 07 34 28 8b 15 90 01 04 03 d3 88 02 90 00 } //01 00 
		$a_01_1 = {8d 43 01 bf 75 00 00 00 33 d2 f7 f7 8b c1 03 c3 88 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_47{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 cb 03 f1 5b 3d 90 01 04 73 08 55 55 ff 15 90 01 04 23 f7 8a 86 90 00 } //01 00 
		$a_03_1 = {30 04 37 4e 79 f5 90 09 05 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_48{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d0 c1 fa 03 8a 14 3a 8a c8 80 e1 07 d2 fa 40 80 e2 01 3b c6 88 54 28 ff 7c e5 } //01 00 
		$a_01_1 = {8a 14 01 30 10 40 83 ee 01 75 f5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_49{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 e5 53 56 83 e4 f8 83 ec } //01 00 
		$a_01_1 = {66 81 38 4d 5a } //01 00 
		$a_01_2 = {4d 73 69 44 61 74 61 62 61 73 65 4d 65 72 67 65 2e 70 64 62 } //00 00  MsiDatabaseMerge.pdb
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_50{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c8 8b 44 24 90 01 01 83 44 24 90 01 01 04 81 c3 90 01 04 89 18 0f b7 c1 8b f0 2b f7 90 09 0a 00 8b 4c 24 90 01 01 69 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_51{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b f2 33 ce 03 c1 8b 0d 90 01 04 03 8d 90 01 04 88 01 90 00 } //01 00 
		$a_03_1 = {85 c9 8b 0d 90 01 04 0b fb 2b fe 87 d9 8b fb ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_52{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 04 51 56 6a 00 ff d0 } //01 00 
		$a_03_1 = {31 d2 f7 f1 8b 4d 90 01 01 8b 75 90 01 01 8a 1c 31 2a 1c 15 90 01 04 8b 55 90 01 01 88 1c 32 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_53{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 94 8d 0c 07 e8 90 01 04 47 3b fe 90 00 } //01 00 
		$a_01_1 = {a1 1c 31 41 00 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 1c 31 41 00 c1 e8 10 30 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_54{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 00 6a 00 ff d5 e8 90 01 04 30 04 3e 46 3b f3 7c 90 00 } //01 00 
		$a_03_1 = {8a 14 06 8b 3d 90 01 04 88 14 07 40 3b c1 72 ef 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_55{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 3b 4d 00 53 00 75 90 02 30 81 7b 04 56 00 42 00 75 90 02 30 8b 70 10 90 02 30 8b 5e 3c 90 02 30 01 de 90 02 30 90 02 30 8b 5e 78 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_56{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d0 83 e2 03 8a 14 0a 30 14 38 40 3b c6 72 f0 } //01 00 
		$a_01_1 = {8b c3 c1 e8 08 8b d3 88 19 c1 eb 18 88 41 01 c1 ea 10 33 c0 88 59 03 88 51 02 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_57{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 c0 fd 43 03 00 05 90 01 04 a3 90 01 04 c1 e8 10 25 ff 7f 00 00 c3 90 09 05 00 a1 90 00 } //01 00 
		$a_03_1 = {30 04 37 6a 00 90 09 05 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_58{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 37 5b f8 83 df fc f7 d3 83 eb 23 8d 5b ff 29 d3 89 da 89 1e f8 83 d6 04 83 c1 fc 85 c9 75 e0 } //01 00 
		$a_01_1 = {5e 8d 05 04 10 49 00 ff 30 ff d6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_59{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f0 03 f3 73 05 e8 90 01 04 8a 16 80 f2 4a 88 16 40 3d 90 01 04 75 e6 90 00 } //01 00 
		$a_03_1 = {74 40 8d 45 90 01 01 50 6a 40 68 90 01 04 53 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_60{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b d1 c1 ea 10 30 14 06 8b 55 dc 40 3b c2 7c e4 } //01 00 
		$a_01_1 = {a1 08 ec 40 00 88 14 30 8b 55 dc 46 3b f2 72 d2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_61{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 14 18 8a 12 80 f2 bd 8d 0c 18 88 11 } //01 00 
		$a_01_1 = {8d 41 01 51 b9 ee 00 00 00 33 d2 f7 f1 59 03 ce 88 11 } //01 00 
		$a_01_2 = {30 30 45 40 42 42 54 60 92 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_62{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 14 07 88 10 8b 55 fc 41 40 3b ca 72 f2 68 90 01 04 6a 40 52 56 ff 15 90 00 } //01 00 
		$a_03_1 = {30 14 30 40 3b 45 fc 7c e6 89 0d 90 01 04 ff 55 f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_63{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {52 50 68 cc 22 00 00 ff 35 90 01 04 ff 15 90 00 } //01 00 
		$a_03_1 = {8b 06 83 c6 04 c1 c0 01 33 05 90 01 04 c1 c0 03 c1 c0 01 ab ba 90 01 04 3b f2 76 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_64{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 ff ff 0f 00 bb 90 01 04 33 d2 03 d3 23 d9 33 c3 ff e0 90 00 } //01 00 
		$a_01_1 = {03 c1 03 c7 03 45 08 8f 45 08 33 c7 23 c2 d3 c8 23 c1 ff 4d 08 83 f8 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_65{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f af c1 0f af c3 8d 3c 87 8a c1 32 06 83 7c 24 90 01 02 74 1b 90 00 } //01 00 
		$a_03_1 = {8a 10 8b 85 90 01 04 88 14 38 83 c7 01 3b bd 90 01 04 7c e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_66{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {30 04 3e 46 3b f3 90 09 12 00 6a 00 a3 90 01 04 ff 15 90 01 04 a0 90 00 } //01 00 
		$a_03_1 = {75 19 8b 0d 90 01 04 6a 40 68 00 10 00 00 51 6a 00 ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_67{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 85 a4 df ff ff 25 ff 90 00 90 8b 4d fc 33 d2 8a 94 0d b4 d2 ff ff 33 c2 8b 4d fc } //01 00 
		$a_03_1 = {70 f8 27 41 6a 90 01 01 8d 95 d4 df ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_68{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 07 8a 4c 24 90 01 01 d3 c0 83 c7 04 33 c6 33 c3 8b f0 89 32 83 c2 04 ff 4c 24 90 01 01 75 e0 90 00 } //01 00 
		$a_01_1 = {8a 04 0f 32 c3 88 01 41 4e 75 f5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_69{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b cf c1 e9 05 03 4b 0c 8b d7 c1 e2 04 03 53 08 50 33 ca 8d 14 38 33 ca 2b f1 8b ce c1 e9 05 03 4b 04 8b d6 c1 e2 04 03 13 33 ca 8d 14 30 33 ca 2b f9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_70{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 44 30 ff 8b 55 90 01 01 8a 54 32 ff 32 c2 88 45 90 01 01 8d 45 90 01 01 8a 55 90 01 01 e8 90 01 04 8b 55 90 01 01 8b c7 e8 90 01 04 46 4b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_71{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 8b c2 85 c0 74 75 58 52 ac 8a e0 30 27 5a 47 4a 49 75 ec } //01 00 
		$a_03_1 = {81 c1 00 80 00 00 4a 4a 68 90 01 04 58 89 25 90 01 04 40 e2 fd 50 ff 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_72{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 8d 85 90 01 04 50 ff 15 90 01 04 e8 90 01 04 30 04 33 90 00 } //01 00 
		$a_03_1 = {51 52 50 ff 15 90 01 04 e8 90 01 04 a1 90 01 04 a3 90 01 04 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_73{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 fc 0f be 18 e8 90 01 04 33 d8 8b 45 08 03 45 fc 88 18 90 00 } //01 00 
		$a_03_1 = {03 f0 89 35 90 01 10 a1 90 01 04 c1 e8 10 25 ff 7f 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_74{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 45 fc 0f b6 00 3d cc 00 00 00 74 0d 8b 45 fc 0f b6 00 3d 90 00 00 00 75 06 } //01 00 
		$a_03_1 = {89 4d 94 81 7d 94 31 33 24 72 74 1d 90 02 30 ff 55 a4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_75{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f0 03 f3 73 05 e8 90 01 04 8a 16 80 f2 4d 88 16 40 3d 90 01 04 75 e6 90 00 } //01 00 
		$a_03_1 = {81 c3 a9 0a 00 00 73 05 e8 90 01 04 89 5d fc ff 65 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_76{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 10 25 ff 7f 00 00 90 09 15 00 a1 90 01 04 69 c0 90 01 04 05 90 01 04 a3 90 00 } //01 00 
		$a_03_1 = {6a 00 ff 15 90 01 04 e8 90 01 04 30 04 3e 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_77{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 90 01 01 71 90 01 01 e8 90 01 04 83 c4 08 8b d1 8a 12 80 f2 90 01 01 88 10 ff 06 41 81 3e 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_78{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 99 6a 03 59 f7 f9 a1 90 01 04 03 c6 85 d2 74 05 80 30 43 eb 03 80 30 61 ff d7 8b e8 ff d7 8b c8 33 d2 8b c5 f7 f1 03 f0 81 fe a0 bb 0d 00 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_79{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 03 45 90 01 01 8b ce c1 e1 04 03 4d 90 01 01 8d 14 33 33 c1 33 c2 2b f8 81 c3 90 01 04 ff 4d 08 75 90 01 01 8b 45 0c 89 38 89 70 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_80{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 83 c4 08 8a 00 32 05 90 01 04 50 8b c6 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 83 c4 08 5a 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_81{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c6 03 0f af f0 52 68 00 30 00 00 56 6a 00 ff 15 } //01 00 
		$a_03_1 = {83 e2 03 03 c2 c1 f8 02 0f af c1 0f af 44 24 90 01 01 2b e8 0f b6 c3 33 c5 99 f7 f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_82{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 03 40 be 90 01 04 33 d2 f7 f6 8b c1 03 03 88 10 90 00 } //01 00 
		$a_03_1 = {33 c0 89 03 a1 90 01 04 03 03 8a 00 90 01 01 34 26 8b 15 90 01 04 03 13 88 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_83{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 8a 45 10 88 45 90 01 01 8b 4d 08 03 4d 0c 8a 55 90 01 01 88 11 8b e5 5d 90 00 } //01 00 
		$a_01_1 = {55 8b ec 8b 45 08 03 45 0c 8b 4d 10 8a 10 88 11 5d } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_84{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 55 08 8b c2 c1 e0 04 8b ca 03 45 0c c1 e9 05 03 4d 10 33 c1 8b 4d 14 03 ca 33 c1 5d } //01 00 
		$a_03_1 = {33 c8 2b d9 53 e8 90 01 04 33 c9 2b f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_85{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 02 a1 90 01 04 32 0c 02 66 0f be c1 66 89 04 57 42 3b 15 90 01 04 7c df 90 09 05 00 a1 90 00 } //01 00 
		$a_01_1 = {8b 47 08 8b 0f 8a 04 30 32 04 31 88 04 1e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_86{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d6 33 d1 0f af cf 0f af d0 2b d1 8b fa } //01 00 
		$a_03_1 = {03 d1 03 15 90 09 06 00 8a 45 90 01 01 32 45 90 00 } //01 00 
		$a_01_2 = {0f af ce 0f af d7 2b ca 2b c8 8b f9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_87{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 0c 30 8a 09 80 f1 88 8d 1c 30 88 0b 40 4a 75 ee } //01 00 
		$a_03_1 = {03 c8 c6 01 90 01 01 43 4a 90 00 } //01 00 
		$a_03_2 = {8d 45 f8 50 6a 40 68 90 01 04 53 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_88{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 90 02 20 8b 40 0c 90 02 20 8b 40 14 90 02 20 8b 00 90 02 20 8b 58 28 90 02 20 81 3b 4d 00 53 00 75 90 02 20 81 7b 04 56 00 42 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_89{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 ac 30 07 47 5a 4a e2 f3 } //01 00 
		$a_03_1 = {83 ec 2c b8 90 01 04 89 04 24 ba 7c 84 40 00 89 54 24 08 b8 5b 00 00 00 89 44 24 04 ba 14 00 00 00 89 54 24 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_90{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 03 83 c4 04 8b 40 28 85 c0 74 29 03 c5 85 c0 74 0b 6a 00 6a 01 55 ff d0 } //01 00 
		$a_01_1 = {8b 07 8b c8 8b d0 c1 e9 1d c1 ea 1e 8b f0 83 e1 01 83 e2 01 c1 ee 1f } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_91{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 fe e6 26 00 00 7d 07 53 ff 15 90 01 04 e8 90 01 04 30 04 37 83 ee 01 79 e4 90 00 } //01 00 
		$a_03_1 = {0f b6 c2 03 c8 0f b6 c1 5e 8a 80 90 09 07 00 0f b6 8e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_92{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a d0 8b 85 90 01 04 03 85 90 01 04 8a 95 90 01 04 8a 08 e8 90 01 04 8b 8d 90 01 04 03 8d 90 01 04 88 01 33 d2 74 90 00 } //01 00 
		$a_01_1 = {33 33 31 35 33 31 35 24 } //00 00  3315315$
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_93{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 3a 83 ea 90 01 01 4a f7 d7 83 ef 90 01 01 4f 01 cf 83 ef 01 31 c9 01 f9 57 8f 46 00 83 c6 05 4e 83 c3 90 01 01 4b 8d 3d 90 01 04 81 c7 90 01 04 ff e7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_94{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 34 08 8b c1 99 6a 05 5f f7 ff 8a 82 90 01 04 30 06 41 3b 0d 90 01 04 72 df 90 00 } //01 00 
		$a_03_1 = {56 ff 70 10 8b 40 0c 03 47 34 51 50 ff 75 90 01 01 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_95{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 80 30 90 01 01 ff 45 90 01 01 81 7d 90 01 05 75 eb 90 00 } //01 00 
		$a_03_1 = {51 54 6a 40 52 50 e8 90 01 04 5a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_96{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 68 00 30 00 00 50 53 ff 15 90 01 03 00 89 85 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {68 00 de 44 00 50 ff d7 } //01 00 
		$a_03_2 = {8a c3 32 85 90 02 30 88 84 90 01 04 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_97{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8e b7 17 da 09 da 02 09 91 90 01 01 61 28 1e 00 00 0a 72 90 01 04 6f 1f 00 00 0a 09 28 1e 00 00 0a 72 90 01 04 6f 1f 00 00 0a 8e b7 5d 91 61 9c 09 17 d6 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_98{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d7 6a 00 ff 15 90 01 04 69 0d 64 66 41 00 fd 43 03 00 8d 04 1e 6a 00 81 c1 c3 9e 26 00 89 0d 64 66 41 00 c1 e9 10 30 08 ff 15 90 01 04 46 3b 75 fc 7c ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_99{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 4c 37 03 8a c1 8a d9 80 e1 f0 24 fc 02 c9 c0 e0 04 0a 44 37 01 c0 e3 06 0a 5c 37 02 02 c9 0a 0c 37 8b 7d fc 88 0c 3a 42 88 04 3a 42 88 1c 3a 83 c6 04 42 3b 35 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_100{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 04 24 8b d6 e8 90 01 04 ff 04 24 4b 75 f0 90 00 } //01 00 
		$a_03_1 = {8b c8 03 ca 73 05 e8 90 01 04 8a 09 90 02 10 80 f1 90 01 01 03 d0 73 05 e8 90 01 04 88 0a c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_101{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b f0 33 d6 03 ca 8b 15 90 01 04 03 95 90 01 04 88 0a 90 00 } //01 00 
		$a_01_1 = {55 8b ec 6a 04 68 00 10 00 00 e8 41 cd ff ff 50 6a 00 ff 15 04 70 42 00 a3 e8 ad 42 00 5d } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_102{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 d2 fd 43 03 00 81 c2 90 01 04 8b c2 c1 e8 10 32 04 0b 46 88 01 8b 7d 90 01 01 41 3b f7 7c 90 00 } //01 00 
		$a_03_1 = {51 6a 40 57 50 6a 00 ff 15 90 01 04 ff 55 f4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_103{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {85 db 74 54 8b bc 24 90 01 04 0f af bc 24 90 01 04 0f af fb 8b 44 24 90 01 01 0f af fe 33 c6 88 45 00 90 00 } //01 00 
		$a_01_1 = {51 68 00 30 00 00 8d 34 ba 56 6a 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_104{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 06 03 d1 8b 4c 24 90 01 01 6b d2 03 01 54 24 90 01 01 88 04 0e a1 90 01 04 40 0f af 05 90 01 04 46 90 00 } //01 00 
		$a_03_1 = {8a c3 32 45 ff 90 01 02 88 45 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_105{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 14 3e 80 e2 01 d2 e2 02 c2 4e 41 83 f9 07 7e ef } //01 00 
		$a_03_1 = {83 f9 0c 73 1f 8a 84 0d 90 01 04 32 c2 88 84 0d 90 01 04 41 89 8d 90 01 04 8a 95 90 01 04 eb dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_106{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 fa 14 75 04 33 d2 eb 01 42 40 3b c6 72 e5 90 09 0c 00 8a 8a 90 01 04 30 88 90 00 } //01 00 
		$a_03_1 = {40 3b c1 72 ea 90 09 11 00 ba 90 01 04 30 90 90 90 01 04 8b 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_107{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 17 8d 44 10 ff 50 e8 90 01 04 5a 88 02 ff 07 4b 75 e5 90 09 07 00 8b c6 e8 90 00 } //01 00 
		$a_03_1 = {25 ff 00 00 00 8b 15 e8 ea 46 00 33 c2 f7 d0 c3 90 09 05 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_108{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {5a 2b 55 14 89 45 14 03 d0 ff e2 90 09 07 00 b9 90 01 04 f3 a4 90 00 } //01 00 
		$a_01_1 = {3b f1 72 17 87 06 33 45 20 03 45 24 87 06 83 ee 04 eb ed } //01 00 
		$a_01_2 = {66 81 3e 4d 5a } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_109{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 06 83 c6 90 01 01 03 05 90 01 04 33 05 90 01 04 c1 c0 90 01 0d c1 c0 90 01 0d c1 c0 90 01 01 2b 05 90 01 04 c1 c0 90 01 01 c1 0d 90 01 05 ab 81 fe 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_110{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 09 8b 45 90 01 01 83 c0 01 89 45 90 01 01 81 7d 84 90 01 04 7d 1b 8b 4d 90 01 01 83 c1 5e 89 4d 90 01 01 6a 00 6a 00 ff 15 90 01 03 00 ff 15 90 01 03 00 eb d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_111{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 0d 8a 86 90 01 04 8b 4e 04 34 90 01 01 88 01 90 00 } //01 00 
		$a_03_1 = {03 c2 99 f7 fb 8b be 90 01 04 8a 84 32 90 01 04 0f b7 96 90 01 04 32 04 0f 03 d7 88 44 0a fa 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_112{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba c0 15 40 00 83 c4 0c 2b d3 03 d7 89 55 f0 8b 45 f0 33 db 8b d8 ff d3 } //01 00 
		$a_03_1 = {8b fb 6a 04 c1 e7 0f 03 79 0c 68 90 01 04 68 90 01 04 57 ff 15 90 01 04 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_113{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a c3 32 45 90 01 01 83 c4 10 90 02 30 88 04 11 90 00 } //01 00 
		$a_03_1 = {8b 55 fc 8a 04 1a 8b 15 90 01 03 00 8d 14 95 0e 00 00 00 89 55 90 01 01 39 4d 90 01 01 74 04 88 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_114{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 08 8a 02 32 45 90 01 01 8b 4d 08 88 01 90 00 } //01 00 
		$a_01_1 = {8a c1 3c 61 7c 06 3c 7a 7f 02 24 df } //01 00 
		$a_01_2 = {8b 55 f8 8b 45 e8 03 42 1c 8b 4d fc 8b 55 e8 03 14 88 8b c2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_115{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {ad c2 10 00 8b 46 14 8b 40 0c 8b 08 33 43 48 c2 08 00 } //01 00 
		$a_03_1 = {89 44 24 04 89 04 24 3b 43 4c 0f 86 90 01 03 ff c1 e8 0a 25 ff 00 00 00 3b 43 50 0f 83 90 01 03 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_116{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc e8 90 01 03 ff 8b c8 8b 55 fc a1 90 01 03 00 e8 90 01 03 ff 6a 40 68 00 30 00 00 53 6a 00 e8 90 01 03 ff 8b f0 85 f6 74 70 8b cb 8b d6 8b 45 fc e8 90 01 03 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_117{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 03 45 e8 8b 4d f8 03 4d e8 8a 11 88 10 eb dd } //01 00 
		$a_01_1 = {8b 4d dc c1 e1 04 03 4d e8 8b 55 dc 03 55 f0 33 ca 8b 45 dc c1 e8 05 03 45 ec 33 c8 8b 55 f4 2b d1 89 55 f4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_118{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 03 45 f8 90 01 01 8a 18 80 f3 1e 88 18 90 00 } //01 00 
		$a_03_1 = {40 b9 5d 00 00 00 33 d2 f7 f1 a1 90 01 04 03 05 90 01 04 88 10 90 09 0f 00 a1 90 01 04 a3 90 01 04 a1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_119{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 06 8a 00 90 01 02 34 2b 8b 15 90 01 04 03 16 88 02 43 81 fb 90 01 04 75 90 09 07 00 89 1e a1 90 00 } //01 00 
		$a_01_1 = {89 1e 8b 06 40 bf 28 00 00 00 33 d2 f7 f7 8b c1 03 06 88 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_120{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 19 f6 d3 8a 04 02 f6 d0 8a d0 22 01 f6 d2 22 d3 0a d0 } //01 00 
		$a_03_1 = {8a 04 06 32 45 90 01 01 8b 4d 90 01 01 83 c4 18 88 04 0e 46 90 00 } //01 00 
		$a_01_2 = {81 e9 33 08 00 00 99 f7 f9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_121{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f 6e 5c 24 04 90 02 20 0f ef d9 90 02 20 0f 7e db 90 02 20 81 fb 90 01 04 75 90 00 } //01 00 
		$a_03_1 = {8b 5c 24 08 90 02 20 39 18 75 90 02 20 8b 5c 24 0c 90 02 20 39 58 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_122{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 d2 74 7f 52 ac 30 07 47 5a 4a e2 f3 5b 5e 33 c0 c3 } //01 00 
		$a_03_1 = {b8 c1 00 00 00 89 44 24 04 b9 90 01 04 89 4c 24 08 b8 14 00 00 00 89 44 24 0c 8d 15 90 01 04 89 14 24 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_123{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 6a 00 52 ff d6 8b 8d 90 01 04 8b 95 90 01 04 89 85 90 00 } //01 00 
		$a_03_1 = {7e 7c 8d 9b 90 01 04 8b 8d 90 01 04 2b 8d 90 01 04 3b f9 72 05 e8 90 01 04 8b 95 90 01 04 8a 04 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_124{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 8b 55 ec 8a 45 eb e8 90 01 04 ff 45 f0 ff 4d e4 90 00 } //01 00 
		$a_03_1 = {89 4d f4 89 55 f8 88 45 ff 8b 45 f4 03 45 f8 8a 00 90 01 08 34 90 01 01 8b 55 f4 03 55 f8 88 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_125{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 c9 fd 43 03 00 81 c1 90 01 04 8b d1 c1 ea 90 01 01 32 14 07 46 88 10 40 3b 75 f8 7c 90 00 } //01 00 
		$a_03_1 = {8b 55 f8 8d 4d 90 01 01 51 6a 40 52 53 ff d0 ff 55 90 01 01 5f 5e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_126{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 7c 24 30 01 8d 04 95 0e 00 00 00 8a 8e 90 01 04 a3 90 01 04 74 0a a1 90 01 04 88 0c 30 90 00 } //01 00 
		$a_03_1 = {8a c3 32 44 24 90 01 01 85 ff 0f b6 c9 0f b6 c0 0f 45 c8 88 0e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_127{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 54 ff 15 90 01 04 5a 5a 5a 50 ff 15 90 01 04 83 ec 90 01 01 a3 90 01 04 68 90 01 04 6a 00 ff 15 90 00 } //01 00 
		$a_01_1 = {ad 03 05 88 79 41 00 c1 c0 04 ab 56 58 2d 92 60 41 00 72 ec } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_128{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 06 83 c6 90 01 01 2b 05 90 01 04 c1 c0 90 01 01 33 05 90 01 04 c1 0d 01 90 01 04 ab bb 90 01 04 3b f3 7c 90 00 } //01 00 
		$a_01_1 = {8b c0 52 50 68 1b 09 01 00 ff 35 1e 4a 41 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_129{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 94 15 90 01 04 03 c2 25 90 01 04 79 07 48 0d 90 01 04 40 0f b6 84 05 90 01 04 8b 95 90 01 04 0f be 0c 11 33 c8 8b 95 90 01 04 8b 82 90 01 04 8b 95 90 01 04 88 0c 10 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_130{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 55 90 01 01 33 c2 3d ff 00 00 00 76 90 01 01 e8 90 01 04 8b 55 90 01 01 85 d2 7c 90 01 01 3b 55 90 01 01 7e 90 01 01 e8 90 01 04 8b 4d 90 01 01 88 04 11 87 c9 89 db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_131{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 43 01 be 90 01 04 33 d2 f7 f6 8b c1 03 c3 88 10 43 81 fb 90 01 04 75 90 00 } //01 00 
		$a_03_1 = {03 c3 8a 00 90 02 10 34 dc 8b 15 90 01 04 03 d3 88 02 90 02 10 43 81 fb 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_132{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 07 89 45 90 01 01 33 45 90 01 01 43 33 45 90 01 01 8a cb d3 c8 8b 4d 90 01 01 83 c7 04 89 4d 90 01 01 89 06 83 c6 04 4a 75 90 00 } //01 00 
		$a_01_1 = {8a 14 07 32 55 0c 88 10 40 49 75 f4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_133{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {29 c0 2b 03 f7 d8 f8 83 db 90 01 01 f7 d8 f8 83 d8 90 01 01 c1 c8 90 01 01 d1 c0 31 c8 f8 83 d8 01 8d 08 c1 c1 90 01 01 d1 c9 f7 d9 50 8f 07 83 ef 90 01 01 f8 83 d6 90 01 01 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_134{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 90 01 01 0f b6 02 0f b6 0d 90 01 04 33 c1 8b 55 0c 03 55 90 01 01 88 02 8b 45 0c 03 45 90 01 01 0f b6 08 0f b6 15 90 01 04 2b ca 8b 45 0c 03 45 90 01 01 88 08 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_135{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f6 c4 41 75 10 68 90 01 02 00 00 8d 95 90 01 02 ff ff ff d2 83 c4 04 8a 86 90 01 04 8a 15 90 01 04 32 c2 3c 3a 88 84 35 90 01 02 ff ff 77 09 fe c8 88 84 35 90 01 02 ff ff 46 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_136{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {30 04 3e 6a 00 90 09 05 00 e8 90 01 01 ff ff ff 90 00 } //01 00 
		$a_03_1 = {8b c8 0f af 0d 90 01 04 e8 90 01 01 ff ff ff 03 c8 89 0d 90 01 04 e8 90 01 01 ff ff ff 0f b7 15 90 01 04 23 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_137{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 0c 28 f6 d1 30 0c 18 40 3b c6 72 f3 } //01 00 
		$a_03_1 = {33 c0 81 34 83 90 01 04 40 83 f8 10 72 f3 90 00 } //01 00 
		$a_03_2 = {50 53 8b c6 e8 90 01 04 59 59 33 c9 8a 14 0b 8b 44 24 0c 30 14 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_138{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 01 58 99 f7 3d 90 01 04 a1 90 01 04 33 c2 8b 0d 90 01 04 8b 15 90 01 04 2b 51 14 8b 0d 90 01 04 8b 49 0c 89 04 91 c7 45 fc 90 01 04 a1 90 01 04 99 6a 01 59 f7 f9 83 f2 01 89 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_139{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {7c 65 8b 45 90 01 01 c1 e0 06 03 d8 89 5d 90 01 01 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d 90 01 01 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 90 01 01 5a 8b ca 99 f7 f9 89 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_140{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {52 50 68 1b 09 01 00 ff 35 90 01 04 ff 15 90 00 } //01 00 
		$a_03_1 = {8b 06 83 c6 90 01 01 2b 05 90 01 04 c1 c0 90 01 01 03 05 90 01 04 03 05 90 01 04 c1 0d 90 01 05 ab b9 90 01 04 3b f1 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_141{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 1c 0f 2a 1c 15 90 01 04 8b 54 24 90 01 01 88 1c 0a 90 00 } //01 00 
		$a_03_1 = {89 c2 83 e2 07 8a 1c 15 90 01 04 8a 3c 05 90 01 04 28 df 88 7c 04 90 01 01 8b 54 24 90 01 01 d3 e2 89 54 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_142{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4e 08 b8 90 01 04 8b 1e 2b cb f7 e9 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 c2 3d 90 00 } //01 00 
		$a_03_1 = {8b c1 c1 e8 90 01 01 30 04 1a 42 3b 55 10 7c 90 09 0c 00 69 c9 90 01 04 81 c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_143{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 89 03 a1 90 01 04 03 03 8a 00 90 02 10 34 07 8b 15 90 01 04 03 13 88 02 90 02 05 ff 03 81 3b e0 5a 00 00 75 90 00 } //01 00 
		$a_01_1 = {8b 03 40 be 8d 00 00 00 33 d2 f7 f6 8b c1 03 03 88 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_144{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 14 01 30 10 40 4e 75 f7 } //01 00 
		$a_01_1 = {8a 1f 49 88 1a 42 47 85 c9 75 f5 } //01 00 
		$a_03_2 = {8a 14 16 8b ce 83 e1 90 01 01 8b c6 d2 e2 c1 f8 90 01 01 03 c7 08 10 46 3b 74 24 90 01 01 7c e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_145{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10 40 89 45 08 } //01 00 
		$a_01_1 = {8a c1 3c 61 7c 06 3c 7a 7f 02 24 df c3 } //01 00 
		$a_01_2 = {8b 07 8b c8 8b d0 c1 e9 1d c1 ea 1e 8b f0 83 e1 01 83 e2 01 c1 ee 1f } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_146{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 0f 33 c9 41 2b 8d 90 01 04 8b d3 0f af 95 90 01 04 2b c8 0f af ce 2b ca 0f af cb c1 e0 02 03 c8 0f af 8d 90 01 04 29 8d 90 01 04 ff 85 90 01 04 8b 85 90 01 04 3b 45 90 01 01 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_147{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {85 c0 74 11 ff 75 08 e8 90 01 04 59 85 c0 74 90 00 } //01 00 
		$a_03_1 = {2b ce 8a 04 10 8b 54 24 90 01 01 32 44 11 ff 8b 4c 24 90 01 01 88 04 31 83 c6 90 01 01 8b 4c 24 10 83 d3 90 01 01 85 db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_148{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 6a 00 6a 00 51 8d 05 90 01 04 ff 10 90 09 0f 00 66 c7 05 90 01 03 00 6e 63 8d 0d 90 00 } //01 00 
		$a_01_1 = {31 f6 57 8b 13 f8 83 d3 04 f7 d2 f8 83 da 22 8d 52 ff 29 ca 31 c9 29 d1 f7 d9 52 8f 07 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_149{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {30 14 38 83 f9 14 75 04 33 c9 eb 01 41 40 3b c6 72 e4 90 09 0a 00 8a 54 0d 90 01 01 8b bd 90 00 } //01 00 
		$a_03_1 = {30 14 08 83 fe 14 75 04 33 f6 eb 01 46 40 3b c7 72 ea 90 09 04 00 8a 54 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_150{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 90 01 04 a1 90 01 04 69 c0 fd 43 03 00 05 90 01 04 a3 90 01 04 c1 e8 10 25 ff 7f 00 00 90 00 } //01 00 
		$a_03_1 = {03 c0 50 ff 74 24 90 01 01 89 44 24 90 01 01 ff 35 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_151{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 83 c4 08 8b d1 8a 12 80 f2 eb 88 10 ff 06 41 81 3e 90 01 02 00 00 75 90 00 } //01 00 
		$a_01_1 = {55 8b ec 51 81 c2 ba 0a 00 00 89 55 fc 8b 7d fc ff d7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_152{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 6e 61 6d 65 5c 75 6e 64 65 72 72 75 6e 5c 43 68 65 72 6e 62 79 6c } //01 00  Qname\underrun\Chernbyl
		$a_01_1 = {8b 95 70 df ff ff 8b 85 4c df ff ff 33 85 5c df ff ff 88 02 } //01 00 
		$a_01_2 = {8b 95 fc fd ff ff 8d 43 08 89 42 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_153{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 90 01 04 8b ce 8b c6 c1 e9 05 03 4d f8 c1 e0 04 03 45 f4 33 c8 8d 04 33 33 c8 2b f9 8b cf 8b c7 c1 e9 05 03 4d f0 c1 e0 04 03 45 ec 33 c8 8d 04 3b 33 c8 8d 9b 90 01 04 2b f1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_154{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b cf 0f 44 f0 c1 e9 05 03 0d 90 01 04 8b c7 c1 e0 04 03 05 90 01 04 33 c8 8d 04 3e 33 c8 2b d9 8b cb 8b c3 c1 e9 05 03 0d 90 01 04 c1 e0 04 03 05 90 01 04 33 c8 8d 04 1e 33 c8 2b f2 2b f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_155{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 10 8b 4d 90 01 01 83 f1 04 8b 55 90 01 01 03 55 90 01 01 88 0a 90 00 } //01 00 
		$a_03_1 = {83 c4 04 8b 4d 90 01 01 0f b6 91 90 01 04 81 ea 9f 00 00 00 88 55 90 01 01 8b 45 90 01 01 83 c0 04 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_156{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 e2 89 4a 04 c7 42 0c 04 00 00 00 c7 42 08 00 10 00 00 c7 02 00 00 00 00 ff d0 } //01 00 
		$a_03_1 = {8a 0c 37 8a 6c 24 90 01 01 28 e9 89 54 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 88 0c 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_157{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 54 8b 0d 90 01 04 03 8d 90 01 04 8b 15 90 01 04 03 95 90 01 04 8a 82 90 01 04 88 01 90 00 } //01 00 
		$a_03_1 = {88 08 8b 55 90 01 01 83 c2 01 89 55 90 09 09 00 8b 45 90 01 01 03 45 90 01 01 8a 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_158{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 03 8a 00 34 7b 8b 15 90 01 04 03 13 88 02 90 90 ff 03 81 3b 5d 57 00 00 75 e0 90 09 05 00 a1 90 00 } //01 00 
		$a_01_1 = {8b 03 40 bf 8a 00 00 00 33 d2 f7 f7 8b c1 03 03 88 10 90 ff 03 81 3b 57 b9 46 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_159{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c2 8b 4d 90 01 01 0f b7 91 90 01 04 03 55 90 01 01 8b 4d 90 01 01 8b 89 84 01 00 00 88 44 0a fa 90 00 } //01 00 
		$a_03_1 = {8b 45 d0 0f b7 88 90 01 04 83 f1 72 83 f1 06 8b 55 d0 8b 42 04 88 48 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_160{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 4c 0a d9 33 c1 88 85 90 01 03 ff 0f be 90 01 03 ff ff 0f be 90 01 03 ff ff 33 85 90 01 03 ff 0f be 90 01 03 ff ff 8b b5 90 01 03 ff 2b f1 33 c6 03 d0 a1 90 01 03 00 03 85 90 01 03 ff 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_161{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 01 00 00 00 99 f7 3d 90 01 04 a1 90 01 04 33 c2 8b 0d 90 01 04 8b 15 90 01 04 89 04 8a c7 45 90 01 05 a1 90 01 04 25 00 00 00 80 79 05 48 83 c8 ff 40 83 f0 01 a3 90 01 04 c7 45 90 09 0d 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_162{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 75 00 69 00 5a 00 64 00 6b 00 6d 00 6b 00 49 00 77 00 49 00 49 00 72 00 42 00 } //01 00  huiZdkmkIwIIrB
		$a_03_1 = {08 07 8e 69 17 59 2e 1e 7e 90 01 04 7e 90 01 04 07 08 91 1f 90 01 01 61 d2 9c 7e 90 01 04 17 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_163{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e0 04 03 c2 8b d1 03 4c 24 90 01 01 c1 ea 05 03 54 24 90 01 01 33 c2 33 c1 90 00 } //01 00 
		$a_03_1 = {8b cf 53 e8 90 01 04 8b 54 24 90 01 01 2b f0 53 ff 74 24 90 01 01 8b ce e8 90 01 04 2b f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_164{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 14 24 8a 1c 11 8a bc 02 90 01 04 28 fb 8b 44 24 90 01 01 8b 74 24 90 01 01 88 1c 16 90 00 } //01 00 
		$a_01_1 = {89 e1 c7 41 0c 40 00 00 00 c7 41 08 00 10 00 00 c7 41 04 00 e0 00 00 c7 01 00 00 00 00 ff d0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_165{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d1 89 55 90 01 01 8b 45 90 01 01 8b 0c 85 90 01 04 33 0d 90 01 04 8b 55 90 01 01 8b 45 90 01 01 89 0c 90 90 90 00 } //01 00 
		$a_03_1 = {8b 04 8a 33 05 90 01 04 8b 4d 90 01 01 8b 55 90 01 01 89 04 8a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_166{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 0c 0f be 02 0c 90 01 01 25 90 01 04 8b 4d fc 33 c8 89 4d fc 8b 55 0c 83 c2 01 89 55 0c 90 00 } //01 00 
		$a_03_1 = {8b 4d fc d1 e9 8b 55 fc 83 e2 01 a1 90 01 04 8b 40 48 0f af c2 33 c8 89 4d fc eb d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_167{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 83 c4 08 8b d1 8a 12 80 f2 81 88 10 ff 06 41 81 3e 2e 5b 00 00 75 } //01 00 
		$a_03_1 = {55 8b ec 51 81 c2 4a 53 00 00 89 55 fc 8b 7d fc 90 02 10 87 fb ff e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_168{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 52 50 8b 06 99 03 04 24 13 54 24 90 01 01 83 c4 08 8b d1 8a 12 80 f2 90 01 01 88 10 ff 06 41 81 3e 90 01 04 75 90 00 } //01 00 
		$a_03_1 = {31 c9 83 c1 5f 31 db 03 5d 90 01 01 87 cb 01 cb 87 d9 ff d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_169{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 1c 10 8b 45 10 03 d8 3b 35 90 01 04 74 19 90 00 } //01 00 
		$a_03_1 = {8a c3 32 01 90 01 06 88 85 90 00 } //01 00 
		$a_03_2 = {fd ff ff 8b 8d 90 01 01 fd ff ff 8b 95 90 01 01 fd ff ff 03 c1 89 85 90 01 01 fd ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_170{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 f8 8a 0d 90 01 03 00 02 4d fc 8b 45 08 02 c9 2a 4d f8 03 c3 2a 4d fc 02 4d 10 30 08 85 f6 74 0d 8b 45 fc 99 2b c2 d1 f8 01 45 fc eb 03 ff 45 fc 85 ff 75 06 ff 05 90 01 03 00 43 3b 5d 0c 7c c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_171{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f1 c1 ee 90 01 01 03 35 90 01 04 8b f9 c1 e7 90 01 01 03 3d 90 01 04 33 f7 8d 3c 0a 33 f7 2b c6 8b f0 c1 ee 90 01 01 03 35 90 01 04 8b f8 c1 e7 90 01 01 03 3d 90 01 04 33 f7 8d 3c 02 33 f7 2b ce 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_172{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 ff 35 18 00 00 00 90 02 30 8b 90 01 01 30 90 02 30 02 90 01 01 02 90 02 30 ff 90 00 } //01 00 
		$a_03_1 = {83 f9 00 0f 85 90 02 40 0f 6e 90 02 40 8b 90 01 01 2c 90 02 30 0f 6e 90 02 30 0f ef 90 02 30 0f 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_173{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 08 32 4d 13 02 4d 13 88 08 40 89 45 08 b8 90 01 04 c3 90 00 } //01 00 
		$a_03_1 = {8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 90 01 04 f7 c7 03 00 00 00 75 14 c1 e9 02 83 e2 03 83 f9 08 72 29 f3 a5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_174{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 54 3a ff 32 95 90 01 04 32 d3 88 54 38 ff 47 4e 75 e0 90 09 0b 00 8d 45 90 01 01 e8 90 01 04 8b 55 90 00 } //01 00 
		$a_03_1 = {0f b6 54 1a ff 8b 4d f8 0f b6 4c 19 ff 32 d1 88 54 18 ff 90 09 03 00 8b 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_175{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 ff 75 90 01 01 c1 e8 05 03 45 90 01 01 8b cf c1 e1 04 03 4d 90 01 01 8b d6 33 c1 8d 0c 3e 33 c1 29 45 90 01 01 8b 4d 90 00 } //01 00 
		$a_01_1 = {8b 45 0c 01 45 fc 8b c1 c1 e0 04 03 45 08 03 ca 33 c1 33 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_176{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 70 28 8b 78 10 85 ff } //01 00 
		$a_01_1 = {8b 54 24 08 85 d2 7c 13 8b 4c 24 04 3b 51 08 7d 0a 8b 01 0f af c2 03 41 1c } //01 00 
		$a_03_2 = {74 47 00 2a 00 35 90 01 04 30 34 00 49 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_177{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 73 90 01 01 e8 90 01 04 8a 00 88 45 90 01 01 8a 45 90 01 01 34 7e 8b 55 90 01 01 03 55 90 01 01 73 05 e8 90 01 04 88 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_178{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d 10 8b d6 8b 5d 10 c1 ea 05 03 51 0c 8b ce c1 e1 04 03 4b 08 33 d1 8d 0c 37 33 d1 8b cb 2b c2 8b d0 c1 ea 05 03 51 04 8b c8 c1 e1 04 03 0b 33 d1 8d 0c 07 33 d1 8d bf 90 01 04 2b f2 ff 4d 0c 75 bc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_179{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 90 01 01 0f be 1a e8 90 01 04 33 d8 8b 45 08 03 45 90 01 01 88 18 90 00 } //01 00 
		$a_03_1 = {55 8b ec a1 90 01 04 69 c0 90 01 04 05 90 01 04 a3 90 01 04 a1 90 01 04 c1 e8 90 01 01 25 90 01 04 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_180{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 43 01 b9 85 00 00 00 33 d2 f7 f1 81 fa ff 00 00 00 76 90 01 01 e8 90 01 04 8b c6 03 c3 88 10 90 00 } //01 00 
		$a_03_1 = {03 c3 8a 00 90 02 10 34 46 8b 15 90 01 04 03 d3 88 02 90 02 10 43 81 fb f9 5c 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_181{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 f7 fe 8a 90 01 02 60 00 10 c0 90 01 01 03 32 90 01 01 88 90 01 01 0f 41 81 f9 90 01 04 7c e4 90 00 } //01 00 
		$a_03_1 = {8b c6 99 f7 f9 8a 04 90 01 01 8a 14 90 01 01 32 90 01 01 88 90 01 01 2e 46 3b f3 7c eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_182{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 14 41 8b 85 90 01 04 0f af 85 90 01 04 8b 8d 90 01 04 2b 8d 90 01 04 03 c1 03 d0 a1 90 01 04 03 85 90 01 04 88 10 90 00 } //01 00 
		$a_03_1 = {8b cb 33 f6 66 d1 e8 66 d1 e0 8b 0d 90 01 04 97 8b d9 93 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_183{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 45 f8 50 6a 40 68 90 01 04 53 e8 90 00 } //01 00 
		$a_03_1 = {8d 14 18 8a 12 90 02 10 80 f2 90 01 01 8d 0c 18 88 11 40 3d 90 01 02 00 00 75 90 00 } //01 00 
		$a_03_2 = {b9 01 00 00 00 90 02 10 8b d9 90 02 10 03 d8 c6 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_184{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 01 0f 80 90 01 04 a3 90 01 0b b8 01 00 00 00 99 f7 3d 90 01 04 8b 0d 90 01 04 33 ca 8b 15 90 01 04 a1 90 01 04 89 0c 90 90 90 01 07 8b 0d 90 01 04 81 e1 90 01 04 79 05 49 83 c9 ff 41 83 f1 01 89 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_185{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 56 04 c7 46 0c 04 00 00 00 c7 46 08 00 10 00 00 c7 06 00 00 00 00 ff d0 } //01 00 
		$a_03_1 = {8a 04 11 8a 64 24 90 01 01 28 e0 88 44 24 90 01 01 8b 74 24 90 01 01 88 04 16 90 09 08 00 8b 4c 24 90 01 01 8b 54 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_186{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 6a 64 6a 00 ff 15 90 01 04 8b f0 68 90 01 04 56 ff 15 90 01 04 c6 46 90 01 02 8b c6 5e c3 90 00 } //01 00 
		$a_03_1 = {55 8b ec 8b c1 c1 e0 04 03 c2 8b d1 03 4d 90 01 01 c1 ea 05 03 55 90 01 01 33 c2 33 c1 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_187{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 ef 73 05 e8 90 01 04 85 ed 74 90 01 02 8b c5 e8 90 01 04 8b d8 90 01 01 8b c3 e8 90 01 04 88 45 00 90 00 } //01 00 
		$a_03_1 = {43 75 22 80 3d 90 01 04 53 75 19 80 3d 90 01 04 4c 75 10 80 3d 90 01 04 46 75 07 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_188{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 0d 8b 85 90 01 04 40 89 85 90 01 04 8b 85 90 01 04 3b 05 90 01 04 73 21 a1 90 01 04 03 85 90 01 04 8b 0d 90 01 04 03 8d 90 01 04 8a 89 90 01 04 88 08 90 00 } //01 00 
		$a_01_1 = {0f b6 45 a7 0f b6 4d 97 0b c1 88 45 a7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_189{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c2 c1 e8 05 03 05 a0 b3 10 01 8b fa c1 e7 04 03 3d 9c b3 10 01 33 c7 8d 3c 16 33 c7 2b c8 8b c1 c1 e8 05 03 05 98 b3 10 01 8b f9 c1 e7 04 03 3d 94 b3 10 01 33 c7 8d 3c 0e 2b 75 f8 33 c7 2b d0 83 6d fc 01 75 b9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_190{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f9 00 75 90 02 20 0f 6e 90 02 20 0f fe 90 02 20 8b 40 2c 90 02 20 0f 6e 90 02 20 0f ef 90 00 } //01 00 
		$a_03_1 = {83 fb 00 75 90 02 20 0f 7e 90 02 40 ff 34 1c 90 02 20 58 90 02 20 e8 90 01 03 00 90 02 20 89 04 1c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_191{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 54 24 28 90 01 06 81 c2 88 1f c3 01 90 01 0b 89 10 90 00 } //01 00 
		$a_01_1 = {57 56 8b 74 24 10 8b 4c 24 14 8b 7c 24 0c 8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 94 02 00 00 83 f9 20 0f 82 d2 04 00 00 81 f9 80 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_192{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 c0 0b a3 14 00 2b c1 88 44 1d 90 01 01 43 83 fb 08 7c ee 90 00 } //01 00 
		$a_03_1 = {ff 75 0c 8d 34 38 ff 15 90 01 04 8b c8 8b 45 10 33 d2 f7 f1 8b 45 0c 8b 4d 08 8a 04 02 32 04 31 88 06 8b 45 10 40 89 45 10 3b c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_193{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 06 8a 00 34 3d 8b 15 90 01 04 03 16 88 02 90 01 01 43 81 fb 90 01 04 75 90 00 } //01 00 
		$a_03_1 = {8b 06 40 b9 90 01 04 33 d2 f7 f1 81 fa ff 00 00 00 76 90 01 01 e8 90 01 04 8b c7 03 06 88 10 43 81 fb 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_194{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 00 88 45 90 01 02 8a 45 90 01 01 32 45 90 01 01 8b 55 90 01 01 03 55 90 01 01 88 02 90 00 } //01 00 
		$a_03_1 = {8b 45 fc 89 45 90 01 01 8b 45 90 01 01 40 b9 90 01 04 33 d2 f7 f1 8b 45 90 01 01 03 45 90 01 01 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_195{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 4d b0 03 4d 98 33 d2 8a 11 89 55 e4 } //01 00 
		$a_03_1 = {03 55 98 c6 02 00 8b 45 d0 05 90 01 04 89 45 d0 90 00 } //01 00 
		$a_03_2 = {8b 45 94 83 c0 01 89 45 94 81 7d 94 90 01 04 7d 90 01 01 8b 4d e4 81 c1 90 01 04 89 4d cc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_196{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 d0 88 15 90 01 04 a0 90 01 04 32 45 90 01 01 a2 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 8a 15 90 01 04 88 11 90 00 } //01 00 
		$a_03_1 = {89 45 fc 8b 55 fc 23 55 1c 89 55 fc a1 90 01 04 03 45 08 8b 4d fc 8a 14 08 88 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_197{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 01 0f af 7d 90 01 01 88 08 40 ff 4d 90 01 01 75 ee 90 00 } //01 00 
		$a_03_1 = {0f af c1 8d 54 10 90 01 01 8b 45 f0 03 c7 30 10 90 00 } //01 00 
		$a_03_2 = {8b 45 f0 89 45 14 8b 45 90 01 01 39 05 90 01 04 76 05 8b 5d 14 ff d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_198{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d 84 83 c1 01 89 4d 84 81 7d 84 98 3a 00 00 7d 90 01 01 8b 55 e4 90 02 06 89 55 90 00 } //01 00 
		$a_01_1 = {8b 55 a4 03 55 88 33 c0 8a 02 89 45 e4 } //01 00 
		$a_03_2 = {c7 45 fc 00 00 00 00 ff 15 90 01 04 5f 5e 5b 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_199{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 53 8b 45 08 0f be 18 e8 90 01 04 33 d8 8b 4d 08 88 19 90 00 } //01 00 
		$a_03_1 = {55 8b ec 56 e8 90 01 04 8b f0 0f af 35 90 01 04 e8 90 01 04 8d 44 06 01 a3 90 01 04 8b 35 90 01 04 c1 ee 10 e8 90 01 04 23 c6 5e 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_200{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 4d f8 32 4d 10 88 4d f8 8b 15 90 01 04 03 55 08 8a 45 f8 88 02 90 00 } //01 00 
		$a_03_1 = {53 56 57 c7 45 90 01 01 00 00 00 00 8b 45 90 01 01 23 45 18 89 45 90 01 01 8b 0d 90 01 04 03 4d 08 8b 55 90 01 01 8a 04 11 88 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_201{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 04 4a 8b 8d 90 01 04 0f af 8d 90 01 04 8b 95 90 01 04 2b 95 90 01 04 03 ca 03 c1 8b 0d 90 01 04 03 8d 90 01 04 88 01 90 00 } //01 00 
		$a_03_1 = {83 c4 08 8b cb 33 f6 66 d1 e8 66 d1 e0 8b 0d 90 01 04 97 8b d9 93 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_202{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 90 01 01 8a 00 88 45 90 01 01 8a 45 90 01 01 34 80 8b 55 08 03 55 90 01 01 88 02 ff 45 90 01 01 81 7d f4 90 01 04 75 dc 90 00 } //01 00 
		$a_03_1 = {b9 5c 00 00 00 33 d2 f7 f1 a1 90 01 04 03 05 90 01 04 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_203{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 53 75 62 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00  nSub.g.resources
		$a_01_1 = {46 00 4c 00 69 00 62 00 2e 00 46 00 4c 00 69 00 62 00 } //01 00  FLib.FLib
		$a_03_2 = {06 08 06 8e b7 5d 91 61 02 08 17 d6 02 8e b7 5d 91 da 20 90 01 04 d6 20 90 01 04 5d b4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_204{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 29 00 00 00 89 44 24 90 01 01 31 d2 f7 f1 8a 1c 15 90 01 04 8b 4c 24 90 01 01 8b 54 24 90 01 01 8a 3c 11 28 df 8b 74 24 90 01 01 88 3c 16 83 c2 25 8b 7c 24 90 01 01 39 fa 89 54 24 90 01 01 72 90 09 04 00 8b 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_205{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 ff 0f b7 05 90 01 04 8b 15 90 01 04 35 90 01 04 33 c7 8a 88 90 01 04 47 81 ff 90 01 04 88 0c 10 7c 90 00 } //01 00 
		$a_03_1 = {8b c1 6a 03 99 5f f7 ff 85 d2 74 17 66 81 3d 90 01 06 75 21 a1 90 01 04 03 c1 80 30 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_206{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 90 02 04 8b 40 0c 90 02 04 8b 40 14 90 00 } //01 00 
		$a_03_1 = {8b 00 89 85 90 01 04 8d 85 90 01 04 50 8b 85 90 01 04 8b 00 ff b5 90 01 04 ff 90 02 05 db e2 90 00 } //01 00 
		$a_03_2 = {31 de eb 14 90 02 20 89 32 eb 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_207{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 90 01 01 03 05 90 01 04 8b fa c1 e7 90 01 01 03 3d 90 01 04 33 c7 8d 3c 16 33 c7 2b c8 8b c1 c1 e8 90 01 01 03 05 90 01 04 8b f9 c1 e7 90 01 01 03 3d 90 01 04 33 c7 8d 3c 0e 2b 75 f8 33 c7 2b d0 ff 4d fc 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_208{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 3b 4d 0c 7d 1a 8b 55 08 03 55 fc 0f be 1a e8 90 01 04 33 d8 8b 45 08 03 45 fc 88 18 eb 90 00 } //01 00 
		$a_03_1 = {55 8b ec a1 90 01 04 69 c0 90 01 04 05 90 01 04 a3 90 01 04 a1 90 01 04 c1 e8 90 01 01 25 90 01 04 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_209{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 44 08 20 33 d0 88 55 90 01 01 8b 8d 90 01 03 ff 8b 95 90 01 03 ff 0f b7 04 4a 0f be 8d 5b f3 ff ff 0f af 8d 90 01 03 ff 0f be 95 90 01 03 ff 8b b5 90 01 03 ff 2b f2 33 ce 03 c1 8b 8d 90 01 03 ff 03 8d 90 01 03 ff 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_210{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 44 08 20 33 d0 88 55 90 01 01 8b 8d 90 01 03 ff 8b 95 90 01 03 ff 0f b7 04 4a 0f be 8d 90 01 03 ff 0f af 8d 90 01 03 ff 0f be 95 90 01 03 ff 8b b5 90 01 03 ff 2b f2 33 ce 03 c1 8b 8d 90 01 03 ff 03 8d 90 01 03 ff 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_211{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c1 8a 8d 90 01 04 0f af c6 2b 85 90 01 04 2b 85 90 01 04 32 c8 39 9d 90 01 04 89 85 90 01 04 74 0a 8b 85 90 01 04 88 08 eb 0e 90 00 } //01 00 
		$a_03_1 = {76 0a 8b 95 90 01 04 8a 12 eb 0d 8b 95 90 01 04 8a 94 15 90 01 04 88 14 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_212{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 1c 11 8a bc 02 90 01 04 28 fb 90 00 } //01 00 
		$a_03_1 = {89 c1 83 e1 07 8a 14 0d 90 01 04 8a 34 05 90 01 04 28 d6 88 74 04 90 00 } //01 00 
		$a_01_2 = {89 e1 c7 41 0c 40 00 00 00 c7 41 08 00 10 00 00 c7 41 04 00 d0 00 00 c7 01 00 00 00 00 ff d0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_213{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f9 00 75 90 02 20 0f 6e 90 02 20 0f fe 90 02 20 8b 90 01 01 28 90 02 20 0f ef 90 02 20 0f 7e 90 00 } //01 00 
		$a_03_1 = {bb 48 00 00 00 90 02 20 83 eb 04 90 02 20 ff 34 1c 90 02 20 58 90 02 20 e8 90 02 20 89 04 1c 90 02 20 85 db 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_214{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 2b c1 8b c8 2b cf 0f b7 d9 8b 0d 90 01 04 80 c2 37 00 15 90 01 04 8b 54 24 90 01 01 8b fb 8d 94 11 90 01 04 8b 0a 8d 74 37 90 01 01 89 35 90 01 04 8d b4 2f 90 01 04 81 c1 90 01 04 2b c3 89 35 90 01 04 89 0d 90 01 04 89 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_215{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {85 c9 0f 85 90 02 30 41 90 02 30 8b 53 2c 90 02 30 31 ca 90 02 30 83 fa 00 75 90 00 } //01 00 
		$a_03_1 = {83 fa 00 75 90 02 30 89 ce 90 02 30 6a 78 90 02 30 58 90 02 30 31 d2 90 02 50 33 14 03 90 02 30 e8 90 01 03 00 90 02 30 83 f8 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_216{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 89 85 90 01 04 8b 4d ec 03 8d 90 01 04 8b 55 f4 03 95 90 01 04 8a 02 88 01 8b 4d f8 83 c1 01 89 4d f8 eb 90 00 } //01 00 
		$a_03_1 = {8b f6 ff 35 90 01 04 8b f6 ff 35 90 01 04 8b f6 33 d2 8d 05 90 01 04 48 03 10 8b d2 8b d2 52 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_217{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 14 bf 8b 8c 24 90 01 04 0f af cb 0f af 8c 24 90 01 04 03 d1 8b 84 24 90 01 04 33 c7 0f af fa 88 06 8d 1c 3a 8b bc 24 90 01 04 46 47 90 00 } //01 00 
		$a_03_1 = {0f af f9 57 50 ff b4 24 90 01 04 ff 94 24 90 01 04 89 84 24 90 01 04 33 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_218{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a c8 8b 84 95 90 01 04 89 84 9d 90 01 04 0f b6 c1 89 84 95 90 01 04 8b 8c 9d 90 01 04 03 c8 81 e1 90 01 04 79 08 49 81 c9 90 01 04 41 8a 84 8d 90 01 04 30 04 37 47 3b 7d 10 72 93 90 00 } //01 00 
		$a_01_1 = {57 57 57 57 6a 02 56 ff d0 56 8b f8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_219{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 33 d2 f7 75 90 01 01 5b 8a 82 90 00 } //01 00 
		$a_03_1 = {30 04 37 4e 79 f5 90 09 05 00 e8 90 00 } //01 00 
		$a_03_2 = {88 0c 07 8a 4d 90 01 01 47 88 0c 07 8a 4d 90 01 01 22 ca 0a 4d 90 01 01 47 88 0c 07 03 75 90 01 01 8b 45 90 01 01 47 3b 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_220{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 50 ff 75 90 01 01 ff 75 90 01 01 a1 90 01 04 8b 0d 90 01 04 ff d0 90 00 } //01 00 
		$a_01_1 = {8b 55 08 8b 02 03 45 fc 8b 4d 08 89 01 } //01 00 
		$a_03_2 = {8b ca 33 c1 8b d2 c7 45 fc 00 00 00 00 8b d2 01 45 fc 8b d2 8b 0d 90 01 04 8b 55 fc 89 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_221{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e0 04 03 c2 8b d1 03 4c 24 08 c1 ea 05 03 54 24 04 33 c2 33 c1 c3 } //01 00 
		$a_03_1 = {8b cf 56 e8 90 01 04 8b 54 24 90 01 01 2b d8 56 ff 74 24 90 01 01 8b cb e8 90 01 04 2b f8 b9 01 00 00 00 8b 44 24 90 01 01 83 c4 10 2b c8 03 f1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_222{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 e8 90 01 04 8b f0 0f af 35 90 01 04 e8 90 01 04 8d 44 06 01 a3 90 01 04 8b 35 90 01 04 c1 ee 90 01 01 e8 90 01 04 23 c6 90 00 } //01 00 
		$a_03_1 = {0f be 02 89 45 90 01 01 e8 90 01 04 33 45 90 01 01 8b 4d 08 03 4d 90 01 01 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_223{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 10 00 00 8b 45 90 01 01 8b 08 51 6a 00 ff 55 90 00 } //01 00 
		$a_03_1 = {52 6a 04 8d 85 90 01 04 50 8b 8d 90 01 04 83 c1 08 51 8b 95 90 01 04 52 ff 15 90 00 } //01 00 
		$a_01_2 = {56 57 ff d0 5f 5e 8b dd 5d 8b 4d 10 55 8b eb 81 f9 00 01 00 00 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_224{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 fe d8 a6 08 00 7f 14 81 fe 50 f5 00 00 7d 09 50 ff d7 6a 00 ff d3 33 c0 46 eb e4 } //01 00 
		$a_01_1 = {8b cb c1 e9 10 88 0e 46 8b c3 c1 e8 08 88 06 46 88 1e 46 33 db 88 5d 0b } //01 00 
		$a_03_2 = {8b 75 08 57 8b 7d 0c e8 90 01 04 30 04 3e 5f 5e 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_225{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 ca 8b 45 90 01 01 c1 e8 05 03 45 90 01 01 33 c8 8b 55 90 01 01 2b d1 89 55 90 01 01 8b 45 90 01 01 c1 e0 04 03 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 33 c1 8b 55 90 01 01 c1 ea 05 03 55 90 01 01 33 c2 8b 4d 90 01 01 2b c8 89 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_226{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec a1 90 01 04 69 c0 90 01 04 05 90 01 04 a3 90 01 04 a1 90 01 04 c1 e8 10 25 ff 7f 00 00 5d c3 90 00 } //01 00 
		$a_03_1 = {6a 00 ff 15 90 01 04 8b 55 90 01 01 03 55 90 01 01 0f be 1a e8 90 01 04 33 d8 8b 45 90 01 01 03 45 90 01 01 88 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_227{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 0f 8a 8d 90 01 04 8b 55 08 80 f1 90 01 01 88 4a 02 90 00 } //01 00 
		$a_03_1 = {32 da 88 19 8b 8d 90 01 04 8a 94 29 90 01 04 8b 85 90 01 04 8a 8c 28 90 01 04 8d 84 28 90 01 04 32 ca 88 08 90 00 } //01 00 
		$a_03_2 = {8a 19 8a 94 2a 90 01 04 32 da 88 19 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_228{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 11 89 15 90 01 04 a1 90 01 04 83 e8 01 a3 90 01 04 8b 15 90 01 04 83 c2 01 a1 90 01 04 8b ff 8b ca a3 90 01 04 31 0d 90 01 04 a1 90 01 04 8b ff c7 05 90 01 04 00 00 00 00 8b ff 01 05 90 01 04 8b ff 8b 0d 90 01 04 8b 15 90 01 04 89 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_229{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c3 73 05 e8 90 01 04 8a 00 34 39 8b 15 90 01 04 03 d3 73 90 01 01 e8 90 01 04 88 02 90 00 } //01 00 
		$a_03_1 = {8b d3 83 c2 01 73 90 01 01 e8 90 01 04 83 e2 3f 81 fa ff 00 00 00 76 90 01 01 e8 90 01 04 8b c8 03 cb 73 90 01 01 e8 90 01 04 88 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_230{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 90 01 04 a3 90 01 04 ff 35 90 01 04 6a 00 ff 15 90 09 15 00 a1 90 01 04 05 90 01 04 a3 90 01 04 ff 35 90 00 } //01 00 
		$a_03_1 = {03 45 fc 83 65 f4 00 a3 90 01 04 81 f3 90 01 04 81 6d f4 90 01 04 81 45 f4 90 01 04 8b 4d f4 d3 e8 5b 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_231{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 19 00 00 0a 0c 08 06 07 03 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 08 18 6f 90 01 01 00 00 0a 08 18 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {50 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 } //00 00  Protector
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_232{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 83 e0 03 0f b6 44 04 90 01 01 30 81 90 01 04 8d 82 90 01 04 03 c1 83 e0 03 0f b6 44 04 90 01 01 30 81 90 01 04 8d 86 90 01 04 03 c1 83 e0 03 0f b6 44 04 90 01 01 30 81 90 01 04 8d 87 90 01 04 03 c1 83 e0 03 0f b6 44 04 90 01 01 30 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_233{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 54 24 7c 8b 96 90 01 04 8b 9c 24 90 01 01 00 00 00 8b b6 90 01 04 31 fe 81 f3 90 01 04 8b 7c 24 90 01 01 01 c7 90 00 } //01 00 
		$a_03_1 = {89 c8 31 d2 8b 74 24 90 01 01 f7 f6 8b 7c 24 90 01 01 8a 1c 0f 2a 1c 15 90 01 04 8b 54 24 90 01 01 88 1c 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_234{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 ff 89 14 24 89 fa 8b 3c 24 f7 f7 8a 1c 15 90 01 04 8b 54 24 90 01 01 8b 7c 24 90 01 01 8a 3c 3a 28 df 29 f1 8b 74 24 90 01 01 88 3c 3e 01 cf 90 00 } //01 00 
		$a_03_1 = {8a 1c 06 0b 4c 24 90 01 01 89 4c 24 90 01 01 8b 4c 24 90 01 01 88 1c 01 01 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_235{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c8 31 d2 8b 74 24 90 01 01 f7 f6 8b 7c 24 90 01 01 8a 1c 0f 2a 1c 15 90 01 04 8b 54 24 90 01 01 88 1c 0a 83 c1 33 89 4c 24 90 01 01 8b 54 24 90 01 01 39 d1 72 c5 90 00 } //01 00 
		$a_01_1 = {89 43 0c 89 53 08 c7 43 04 00 e0 00 00 c7 03 00 00 00 00 ff d6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_236{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 db 33 db a1 90 01 04 03 c3 8a 00 90 01 04 89 db 90 01 08 34 16 8b 15 90 01 04 03 d3 88 02 89 c0 90 00 } //01 00 
		$a_00_1 = {8b c1 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 8a 00 50 8b c7 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 5a 88 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_237{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 24 8b 45 90 01 01 33 d2 f7 75 90 01 01 8b 45 90 01 01 0f b6 0c 10 8b 55 08 03 55 90 01 01 0f b6 02 33 c1 8b 4d 08 03 4d 90 01 01 88 01 90 00 } //01 00 
		$a_03_1 = {73 15 8b 4d 90 01 01 c1 e1 03 8b 55 90 01 01 d3 ea 8b 45 90 01 01 03 45 90 01 01 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_238{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 06 85 c0 79 05 e8 90 01 05 3d 90 01 04 76 90 01 01 e8 90 01 04 8d 90 90 90 01 04 8a 12 80 f2 34 03 c3 73 90 01 01 e8 90 01 04 88 10 ff 06 90 00 } //01 00 
		$a_03_1 = {55 8b ec 51 81 c2 09 43 00 00 73 05 e8 90 01 04 89 55 90 01 01 8b 55 90 01 01 ff d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_239{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {85 c9 74 2a 8b 55 90 01 01 0f b6 8c 15 90 01 04 8b 45 90 01 01 99 be 90 01 04 f7 fe 0f b6 54 15 90 01 01 33 ca 51 8b 45 90 01 01 50 8d 4d 90 01 01 e8 90 00 } //01 00 
		$a_03_1 = {55 8b ec 51 89 4d 90 01 01 8b 45 90 01 01 8b 08 8b 55 08 8a 45 0c 88 04 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_240{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {fe c3 0f b6 f3 8a 14 3e 02 fa 0f b6 cf 8a 04 39 88 04 3e 88 14 39 0f b6 0c 3e 0f b6 c2 03 c8 0f b6 c1 8b 4c 24 90 01 01 8a 04 38 30 04 29 45 3b 6c 24 14 72 90 00 } //01 00 
		$a_03_1 = {0f b6 04 1f 33 c1 c1 e9 08 0f b6 c0 33 0c 85 90 01 04 47 3b fa 72 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_241{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {bf 01 00 00 00 8d 45 fc e8 90 01 04 8b 55 90 01 01 8a 54 3a ff 32 55 90 01 01 32 d3 88 54 38 ff 47 4e 75 90 00 } //01 00 
		$a_03_1 = {46 8b c7 e8 90 01 04 8b d3 2b 55 90 01 01 8b 4d 90 01 01 8a 54 11 ff 8b 4d 90 01 01 8a 4c 19 ff 32 d1 88 54 18 ff 43 4e 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_242{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 08 32 4d 90 01 01 02 4d 90 01 01 88 08 b8 90 01 03 00 c3 90 00 } //01 00 
		$a_03_1 = {8b 45 08 8b 78 3c 03 f8 81 3f 50 45 00 00 75 34 8b 35 90 01 03 00 6a 04 68 00 20 00 00 ff 77 90 01 01 ff 77 90 01 01 ff d6 90 00 } //01 00 
		$a_01_2 = {53 68 65 6c 6c 65 78 00 } //00 00  桓汥敬x
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_243{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 66 2e 65 78 65 } //01 00  sf.exe
		$a_01_1 = {66 00 73 00 66 00 73 00 64 00 66 00 73 00 64 00 66 00 73 00 64 00 66 00 73 00 64 00 66 00 } //01 00  fsfsdfsdfsdfsdf
		$a_01_2 = {23 00 6e 00 73 00 64 00 66 00 66 00 64 00 73 00 70 00 23 00 24 00 24 00 24 00 2e 00 65 00 78 00 65 00 24 00 24 00 24 00 } //00 00  #nsdffdsp#$$$.exe$$$
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_244{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {65 33 32 46 c7 05 90 01 04 69 72 73 74 66 c7 90 01 04 00 57 00 c7 05 90 01 04 4d 6f 64 75 c6 05 90 01 04 6c ff d6 90 00 } //01 00 
		$a_03_1 = {73 25 8b 45 90 01 01 89 85 90 01 04 8b 45 90 01 01 03 85 90 01 04 8b 4d 90 01 01 03 8d 90 01 04 8a 89 90 01 04 88 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_245{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 7c 24 08 8a 9c 07 90 01 04 90 02 20 8b 7c 24 90 01 01 8a 3c 07 90 02 20 28 df 8b 4c 24 90 01 01 88 3c 01 90 02 20 8b 54 24 90 01 01 01 f2 8b 74 24 90 00 } //01 00 
		$a_03_1 = {83 c0 01 89 44 24 90 01 01 83 f8 3e 0f 85 90 09 08 00 89 44 24 90 01 01 8b 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_246{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8b 4d 18 03 4d f0 0f b6 09 33 8c 85 90 01 03 ff 8b 45 18 03 45 f0 88 08 90 00 } //01 00 
		$a_03_1 = {8b 4d 08 03 48 10 89 4d 90 01 01 e8 90 01 03 00 6a 00 ff 75 0c ff 75 08 ff 55 90 01 01 89 45 90 01 01 e8 90 01 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_247{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 24 32 28 c4 8b 7c 24 90 01 01 88 24 37 01 ce 90 09 08 00 8b 54 24 90 01 01 8b 74 24 90 00 } //01 00 
		$a_03_1 = {83 d1 00 8b 14 90 01 01 42 89 44 24 90 01 01 89 4c 24 90 01 01 83 fa 33 89 54 24 90 01 01 75 c1 90 09 0d 00 8b 44 24 90 01 01 8b 4c 24 90 01 01 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_248{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 8b 4d 90 01 01 03 4d 90 01 01 0f be 09 33 c8 8b 45 90 01 01 03 45 90 01 01 88 08 8b 45 90 01 01 48 89 45 90 01 01 eb d6 90 00 } //01 00 
		$a_03_1 = {6a 00 ff 15 90 01 04 a1 90 01 04 03 45 90 01 01 8b 0d 90 01 04 03 4d 90 01 01 8a 89 90 90 18 00 00 88 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_249{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f6 81 fe 90 01 04 75 19 6a 40 68 00 10 00 00 ff 35 90 01 04 53 ff 15 90 09 0a 00 81 05 90 00 } //01 00 
		$a_03_1 = {76 21 8b 0d 90 01 04 8a 8c 01 90 01 04 8b 15 90 01 04 88 0c 02 8b 0d 90 01 04 40 3b c1 72 df 90 00 } //01 00 
		$a_03_2 = {30 04 3e 46 3b 75 08 90 09 05 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_250{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 06 73 05 e8 90 01 04 8a 00 90 01 02 34 5f 8b 15 90 01 04 03 16 73 05 e8 90 01 04 88 02 90 01 02 43 81 fb 90 00 } //01 00 
		$a_03_1 = {8b 06 83 c0 01 73 05 e8 90 01 04 b9 e1 00 00 00 33 d2 f7 f1 81 fa 90 01 04 76 05 e8 90 01 04 8b c7 03 06 73 05 e8 90 01 04 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_251{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 90 02 10 8b 40 0c 90 02 10 8b 40 14 90 02 10 8b 40 14 90 02 10 48 66 81 38 ff 25 75 90 01 01 e9 90 00 } //01 00 
		$a_01_1 = {40 81 38 8b 7c 24 0c 75 f7 81 78 04 85 ff 7c 08 75 ee } //01 00 
		$a_03_2 = {5f 81 34 1f 90 02 15 66 39 d3 90 02 10 75 90 02 10 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_252{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {32 d2 c1 6d 90 01 01 08 89 5d 90 01 01 89 4d 90 01 01 c7 45 90 01 01 64 00 00 00 8a 4d 90 01 01 02 4d 90 01 01 02 4d 90 01 01 02 c8 02 d1 ff 4d 90 01 01 75 ee 30 97 90 01 04 0f b6 ca 03 cf 03 c1 47 3b fe a3 90 01 04 7c b4 6a 40 68 00 30 00 00 56 6a 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_253{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 04 3e 89 45 90 01 01 e8 90 01 04 89 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 89 45 90 01 01 8a 4d 90 01 01 88 0c 3e 46 3b f3 7c dd 90 00 } //01 00 
		$a_03_1 = {d3 ea c7 45 90 01 05 81 45 90 01 05 81 45 90 01 05 b8 90 01 04 81 45 90 01 05 8b 45 90 01 01 23 c2 5b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_254{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 90 83 c2 01 89 55 90 81 7d 90 88 13 00 00 7d 1c b8 5f 00 00 00 2b 45 98 8b 4d e0 03 c8 89 4d cc } //01 00 
		$a_03_1 = {8b 4d 98 83 c1 01 89 4d 98 81 7d 98 90 01 04 7d 5e 8d 55 a0 52 ff 15 90 01 04 8b 45 b0 03 45 98 33 c9 8a 08 89 4d e0 90 00 } //01 00 
		$a_01_2 = {6a 6b 67 61 61 } //00 00  jkgaa
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_255{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 18 00 00 00 90 02 40 64 8b 00 90 02 40 8b 40 30 90 02 40 5b 90 02 40 02 58 02 90 02 40 ff e3 90 00 } //01 00 
		$a_03_1 = {81 eb 00 10 00 00 90 02 40 53 90 02 40 6a 00 90 02 40 6a 00 90 02 40 ff 72 68 90 02 40 ff 72 6c 90 02 40 ff 72 70 90 02 40 ff 72 74 90 02 40 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_256{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c2 99 f7 7d 90 01 01 0f b6 84 15 90 01 04 8b 4d 10 03 4d 90 01 01 0f b6 11 33 d0 8b 45 10 03 45 90 01 01 88 10 90 00 } //01 00 
		$a_03_1 = {03 04 8a 50 e8 90 01 04 83 c4 04 3b 45 0c 75 17 8b 4d 90 01 01 8b 55 90 01 01 0f b7 04 4a 8b 4d 90 01 01 8b 55 08 03 14 81 8b c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_257{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c3 bf 0a 00 00 00 99 f7 ff 80 c2 30 33 c0 8a c1 88 14 06 8b c3 bb 0a 00 00 00 99 f7 fb 8b d8 49 85 db 75 db } //01 00 
		$a_03_1 = {53 31 db 69 93 90 01 08 42 89 93 90 01 04 f7 e2 89 d0 5b 90 00 } //01 00 
		$a_03_2 = {8b d0 03 d7 89 d6 85 d2 75 05 e8 90 01 04 6a 00 6a 01 57 ff d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_258{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 6a 00 e8 90 01 04 80 bd 90 01 04 43 75 22 80 bd 90 01 04 46 75 19 80 bd 90 01 04 4c 75 10 80 bd 90 01 04 53 90 00 } //01 00 
		$a_03_1 = {8b de 03 d9 73 05 e8 90 01 04 89 5d f8 85 c0 75 1f 90 00 } //01 00 
		$a_03_2 = {8b ce 81 c1 7c 40 00 00 73 05 e8 90 01 04 89 4d 90 01 01 8b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_259{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d2 8d 1d 90 01 04 03 db 8d 0d 90 01 04 03 c9 8d 0d 90 01 04 03 c9 c1 c0 02 8d 15 90 01 04 03 d2 8d 15 90 01 04 03 d2 8d 0d 90 01 04 03 c9 8d 0d 90 01 04 03 c9 2b 05 90 01 04 8d 0d 90 01 04 03 c9 8d 0d 90 01 04 03 c9 8d 1d 90 01 04 03 db 8d 1d 90 01 04 03 db ab 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_260{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c8 0f b6 1c 0e 99 f7 bd 90 01 04 0f b6 14 17 89 d0 f7 d0 21 d8 f7 d3 21 d3 09 d8 88 04 0e 83 c1 01 3b 8d 90 01 04 75 90 00 } //01 00 
		$a_03_1 = {89 d8 0f b6 31 83 c3 01 99 83 c1 01 f7 bd 90 01 04 0f b6 14 17 89 d0 f7 d0 21 f0 f7 d6 21 d6 09 f0 88 41 ff 3b 8d 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_261{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 05 11 05 07 11 06 91 17 d6 5d d6 13 05 11 06 17 d6 13 06 } //01 00 
		$a_01_1 = {11 05 d6 13 05 11 05 1b d6 08 20 ff 00 00 00 5f d8 08 1e 63 d6 0c 11 05 1d d6 11 04 20 ff 00 00 00 5f d8 11 04 1e 63 d6 13 04 08 1e 62 11 04 d6 20 ff 00 00 00 5f 13 05 09 11 07 02 11 07 91 11 05 b4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_262{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 14 18 8b c8 c1 f9 03 8d 34 29 8b c8 83 e1 07 d2 e2 40 08 16 3b c7 7c e7 } //01 00 
		$a_03_1 = {27 c6 44 24 90 01 01 76 c6 44 24 90 01 01 63 c6 44 24 90 01 01 68 c6 44 24 90 01 01 6f c6 44 24 90 01 01 74 c6 44 24 90 01 01 2e 88 4c 24 90 01 01 c6 44 24 90 01 01 78 88 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_263{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 f3 88 dd 88 4c 24 90 01 01 88 e9 8b 5c 24 90 01 01 d3 e3 89 5c 24 90 01 01 8a 4c 24 90 01 01 88 0a 8b 54 24 90 01 01 81 c2 90 01 04 8b 5c 24 90 01 01 83 d3 00 8b 7c 24 90 01 01 01 c7 90 00 } //01 00 
		$a_03_1 = {8a 1c 11 8a bc 02 90 01 04 28 fb 8b 44 24 90 01 01 88 1c 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_264{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 da 11 04 da 03 11 04 91 90 01 01 61 90 01 01 11 04 90 01 01 8e b7 5d 91 61 9c 11 04 17 d6 90 00 } //01 00 
		$a_03_1 = {52 65 74 00 43 61 6c 6c 00 43 61 6c 6c 76 69 72 74 90 02 10 2e 50 6e 67 90 00 } //01 00 
		$a_03_2 = {65 00 72 00 72 00 6f 00 72 00 90 02 60 2e 00 50 00 6e 00 67 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_265{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 0a 00 00 00 6a 00 33 c9 58 f7 f1 } //01 00 
		$a_03_1 = {68 d2 07 00 00 ff 15 90 01 04 ff 15 90 01 04 2b 05 90 01 04 3d 0c 03 00 00 76 90 00 } //01 00 
		$a_01_2 = {b9 a9 6d f1 f3 8b c0 49 75 } //01 00 
		$a_03_3 = {6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 ff 15 90 01 04 8b c8 c1 e1 04 2b c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_266{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {bb 9a 02 00 00 ba 6f 00 00 00 be f4 01 00 00 } //01 00 
		$a_03_1 = {89 55 e0 a1 90 01 03 00 89 45 e4 8b 0d 90 01 03 00 89 4d e8 8a 15 90 01 03 00 88 55 ec 90 00 } //01 00 
		$a_03_2 = {0f b7 14 41 0f be 85 90 01 04 0f af 85 90 01 04 0f be 8d 90 01 04 8b b5 90 01 04 2b f1 03 c6 03 d0 88 95 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_267{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 55 8b d8 ff 15 90 01 04 50 e8 90 01 04 68 90 01 04 8b f8 e8 90 00 } //01 00 
		$a_03_1 = {0f b6 14 30 0f b6 5c 30 01 81 c2 90 01 04 c1 e2 90 01 01 03 d7 8a 14 13 88 14 30 40 3b c1 7c 90 00 } //01 00 
		$a_03_2 = {23 d3 8b 04 91 8b d0 c1 ea 90 01 01 0f b6 ca 0f b6 d0 d3 eb 2b f9 85 d2 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_268{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 1f 49 88 1a 42 47 85 c9 75 f5 } //01 00 
		$a_03_1 = {83 c1 08 51 ff 75 90 01 01 a3 90 01 04 ff d0 90 09 0d 00 8d 4d 90 01 01 51 6a 04 8d 4d 90 01 01 51 8b 4d 90 00 } //01 00 
		$a_01_2 = {8b 45 10 8d 0c 30 8a 04 33 30 01 8a 01 30 04 33 8a 04 33 30 01 4b ff 45 10 8b c3 2b 45 10 83 f8 01 7d d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_269{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 06 83 e9 01 88 02 83 c2 01 83 c6 01 85 c9 75 ef } //01 00 
		$a_03_1 = {52 83 c1 08 51 57 a3 90 01 04 ff d0 90 09 12 00 8d 4c 24 90 01 01 51 8b 8c 24 90 01 04 6a 04 8d 54 24 90 00 } //01 00 
		$a_03_2 = {8b 0e 8d 84 24 90 01 04 50 51 ff d3 8d 94 24 90 01 04 a3 90 01 04 8b 06 52 50 ff d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_270{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d6 20 ff 00 00 00 5f 90 02 05 11 07 02 11 07 91 90 02 05 b4 61 9c 11 07 17 d6 13 07 90 00 } //01 00 
		$a_03_1 = {28 1f 00 00 0a 90 02 05 1b d6 90 01 01 20 ff 00 00 00 5f d8 90 01 01 1e 63 d6 90 02 05 1d d6 90 01 01 20 ff 00 00 00 5f d8 90 01 01 1e 63 d6 90 01 02 1e 62 90 01 01 d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_271{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 04 24 8b 4c 24 08 8a 14 01 8b 74 24 04 88 14 06 83 c0 01 8b 7c 24 0c 39 f8 89 04 24 74 d4 } //01 00 
		$a_03_1 = {8a 3c 08 8b 7c 24 90 01 01 28 df 8b 44 24 90 01 01 35 90 01 04 89 44 24 50 81 f7 90 01 04 8b 44 24 90 01 01 88 3c 08 01 f9 89 4c 24 90 01 01 8b 7c 24 90 01 01 39 f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_272{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f0 40 83 f0 06 50 68 90 01 04 68 90 01 04 6a 00 8b 4d 90 01 01 ff 91 90 01 04 50 8b 55 90 01 01 ff 92 90 00 } //01 00 
		$a_03_1 = {03 d1 81 e2 90 01 04 79 08 4a 81 ca 90 01 04 42 8b 4d 90 01 01 0f b6 94 11 90 01 04 33 c2 8b 4d 90 01 01 8b 91 90 01 04 8b 4d 90 01 01 88 04 0a e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_273{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 8a 98 90 01 04 03 d0 30 1a 40 3b c6 7c ee 90 00 } //01 00 
		$a_03_1 = {33 d2 8b c1 5b f7 f3 85 d2 75 12 8b 45 90 01 01 2b c1 bb 90 01 04 f7 f3 30 91 90 01 04 41 3b ce 72 dc 90 00 } //01 00 
		$a_03_2 = {8b c8 8b c2 33 d2 f7 f1 8a 82 90 01 04 30 03 ff 45 90 01 01 39 75 90 01 01 72 d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_274{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 11 83 7d 90 01 02 74 0d 90 09 0c 00 8b 0d 90 01 04 03 4d 90 01 01 8a 55 90 00 } //01 00 
		$a_03_1 = {33 c0 8a 02 89 45 90 01 01 90 09 06 00 8b 55 90 01 01 03 55 90 00 } //01 00 
		$a_03_2 = {03 c2 89 45 90 01 01 6a 03 6a 00 ff 15 90 01 04 eb cc 90 09 0b 00 ba 90 01 04 2b 55 90 01 01 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_275{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 8b 14 8d 90 01 04 33 15 90 01 04 8b 45 f4 8b 8d 90 01 04 89 14 81 90 00 } //01 00 
		$a_03_1 = {8b 55 f4 8b 85 90 01 04 8b 0c 90 90 03 0d 90 01 04 8b 55 f4 8b 85 90 01 04 89 0c 90 90 90 00 } //01 00 
		$a_03_2 = {83 c1 3e 51 8b 15 90 01 04 52 8b 85 90 01 04 50 8b 0d 90 01 04 51 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_276{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 0b 8b 45 90 01 01 03 d1 8a 04 02 8b 55 90 01 01 39 5d 90 01 01 75 09 8b 55 90 01 01 88 04 11 90 00 } //01 00 
		$a_03_1 = {8a 4d c7 32 c8 39 5d 90 01 01 75 03 8a 4d 90 01 01 88 0f 90 00 } //01 00 
		$a_03_2 = {74 0c 6a 40 68 00 30 00 00 ff 75 90 01 01 eb 08 6a 02 53 68 00 10 00 00 53 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_277{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 d2 f7 f1 8b 4d 90 01 01 8b 75 90 01 01 8a 1c 31 2a 1c 15 90 01 0b 8b 55 90 01 01 88 1c 32 83 c6 90 00 } //01 00 
		$a_00_1 = {6a 04 68 00 10 00 00 51 6a 00 ff d0 } //01 00 
		$a_03_2 = {31 c0 8b 4c 24 90 01 01 81 c1 90 01 04 8b 54 24 90 01 01 89 0a c7 42 04 90 01 04 8b 4c 24 90 01 01 81 c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_278{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b ca c0 ec 04 c0 e4 04 a1 e8 6c 46 00 56 90 c0 ff 03 c0 e7 03 ff d0 33 c0 } //01 00 
		$a_03_1 = {2b c2 0b c8 89 8d 90 01 04 b9 90 01 04 2b 8d 90 01 04 2b 8d 90 01 04 2b 4d 90 01 01 66 89 4d 8c 8b 95 90 01 04 03 55 90 01 01 0f b6 02 03 85 90 01 04 8b 0d 90 01 04 03 8d 90 01 04 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_279{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 14 01 8b 75 90 01 01 88 14 06 8b 7d 90 01 01 81 f7 90 01 04 89 7d 90 01 01 83 c0 01 8b 7d 90 01 01 39 f8 89 45 90 09 06 00 8b 45 90 01 01 8b 4d 90 00 } //01 00 
		$a_03_1 = {89 c8 31 d2 8b 74 24 90 01 01 f7 f6 8b 7c 24 90 01 01 8a 1c 0f 2a 1c 15 90 01 04 8b 54 24 90 01 01 88 1c 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_280{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 04 24 bf 90 01 04 81 ef 90 01 04 83 ec 04 89 3c 24 bb 90 01 04 81 eb 90 01 04 83 ec 04 89 1c 24 be 00 00 00 00 83 ec 04 89 34 24 be 90 01 04 83 ec 04 89 34 24 ff 15 90 00 } //01 00 
		$a_01_1 = {31 c9 2b 0a f7 d9 83 c2 04 8d 49 dd 01 f9 49 8d 39 c6 06 00 01 0e 83 ee fc 83 c3 fc 83 fb 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_281{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 1c 08 80 f3 90 01 01 f6 d3 80 f3 90 01 01 88 1c 08 90 00 } //01 00 
		$a_01_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 40 18 } //01 00 
		$a_03_2 = {73 24 0f b6 55 90 01 01 8b 45 90 01 01 8b 08 0f b6 41 90 01 01 8b 4d 90 01 01 0f b6 54 11 30 33 d0 0f b6 45 90 01 01 8b 4d 90 01 01 88 54 01 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_282{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 54 24 04 8b c2 c1 e0 04 8b ca 03 44 24 08 c1 e9 05 03 4c 24 10 33 c1 8b 4c 24 0c 03 ca 33 c1 c3 } //01 00 
		$a_03_1 = {8b cf 8b c7 c1 e9 05 03 4c 24 90 01 01 c1 e0 04 03 44 24 90 01 01 33 c8 8d 04 2f 33 c8 8b 44 24 90 00 } //01 00 
		$a_03_2 = {03 c0 50 57 ff 35 90 01 04 ff 15 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_283{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {29 d1 89 4c 24 90 01 01 8b 4c 24 90 01 01 8a 1c 01 8b 74 24 90 01 01 88 1c 06 83 c0 01 89 d1 d3 ea 89 54 24 90 01 01 8b 54 24 90 01 01 39 d0 89 44 24 90 00 } //01 00 
		$a_03_1 = {31 fa 31 f1 8b 74 24 90 01 01 89 f0 89 4c 24 90 01 01 88 c1 8b 7c 24 90 01 01 d3 ef 8b 44 24 90 01 01 09 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_284{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {7d 5a 8b 8d 90 01 04 83 e9 2a 89 4d 90 01 01 0f b7 55 90 01 01 83 ea 4c 0f b6 85 90 01 04 2b d0 83 e2 e1 88 55 fd 8b 8d 90 01 04 2b 0d 90 01 04 0b 4d 90 01 01 0b 4d 90 01 01 0f b7 55 90 01 01 0b d1 66 89 55 90 01 01 8b 45 90 01 01 83 c0 61 8b 8d 90 01 04 81 c1 84 00 00 00 33 c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_285{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e0 04 03 c2 8b d1 03 4c 24 08 c1 ea 05 03 54 24 04 33 c2 33 c1 c3 } //01 00 
		$a_03_1 = {51 57 8b d0 8b cb e8 90 01 04 8b 54 24 90 01 01 2b e8 57 ff 74 24 90 01 01 8b cd e8 90 01 04 83 c4 10 2b d8 8b 44 24 90 01 01 6a f7 59 2b c8 8b 44 24 90 01 01 03 f9 8b 4c 24 90 01 01 4e 75 c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_286{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c8 31 d2 8b 74 24 90 01 01 f7 f6 8b 7c 24 90 01 01 8a 1c 15 90 01 04 89 7c 24 90 01 01 8b 54 24 90 01 01 8a 3c 0a 28 df 8b 7c 24 90 01 01 88 3c 0f 90 00 } //01 00 
		$a_03_1 = {89 c1 83 e1 07 8a 14 05 90 01 04 2a 14 0d 90 01 04 88 54 04 90 01 01 83 c0 01 89 44 24 90 01 01 83 f8 0e 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_287{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a c8 80 e1 fc c0 e1 90 01 01 08 0f 8b 4c 24 04 d2 e0 5d 24 c0 08 06 59 c3 90 00 } //01 00 
		$a_03_1 = {89 0c 24 c1 24 24 90 01 01 8b 44 24 0c 01 04 24 89 4c 24 04 c1 6c 24 04 90 01 01 8b 44 24 14 01 44 24 04 03 4c 24 10 89 4c 24 10 8b 44 24 10 31 04 24 8b 44 24 04 31 04 24 8b 04 24 83 c4 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_288{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e9 05 03 4c 24 90 01 01 c1 e0 04 03 c6 33 c8 8b 44 24 90 01 01 03 44 24 90 01 01 33 c8 29 4c 24 90 00 } //01 00 
		$a_03_1 = {8b 44 24 38 8b 4c 24 90 01 01 8b 44 24 90 01 01 c1 e9 05 03 4c 24 90 01 01 c1 e0 04 03 44 24 90 01 01 33 c8 8b 44 24 90 01 01 03 44 24 90 01 01 6a 00 33 c8 29 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_289{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 00 00 56 c6 84 90 01 02 04 00 00 44 c6 84 90 01 02 04 00 00 45 c6 84 90 01 02 04 00 00 53 c6 84 90 01 02 04 00 00 54 88 9c 90 01 02 04 00 00 90 00 } //01 00 
		$a_03_1 = {02 00 00 a0 c6 84 90 01 02 02 00 00 c9 c6 84 90 01 02 02 00 00 0f c6 84 90 01 02 02 00 00 57 c6 84 90 01 02 02 00 00 da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_290{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 9e 90 01 04 8b c6 f7 f5 0f be 04 0a 03 c7 0f b6 cb 03 c8 0f b6 f9 8b 4c 24 90 01 01 89 3d 90 01 04 8a 87 90 01 04 88 86 90 01 04 46 88 9f 90 01 04 89 35 90 01 04 81 fe 90 01 04 75 bb 90 00 } //01 00 
		$a_03_1 = {8b 4c 24 0c 8b d0 e8 90 01 04 eb 08 e8 90 01 04 30 04 37 83 ee 01 79 f3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_291{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 2b c2 d1 f8 0f af 45 10 03 85 90 01 02 ff ff 89 85 90 01 02 ff ff 0f b6 85 90 01 02 ff ff 33 85 90 01 02 ff ff 88 85 90 01 02 ff ff 8a 85 90 01 02 ff ff 88 85 90 01 02 ff ff 8a 45 08 88 85 90 01 02 ff ff 83 7d 10 00 74 13 8b 45 08 03 85 90 01 02 ff ff 8a 8d 90 01 02 ff ff 88 08 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_292{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f be 45 08 0f be 4d 0c 33 c1 } //01 00 
		$a_03_1 = {83 c0 01 89 45 90 01 01 8b 4d 90 01 01 3b 4d 90 01 01 7d 2e 8b 45 90 01 01 99 f7 7d 90 01 01 8b 45 90 01 01 8a 0c 10 88 4d 90 01 01 0f b6 55 90 01 01 52 8b 45 90 01 01 03 45 90 01 01 0f b6 08 51 e8 90 01 04 8b 55 90 01 01 03 55 90 01 01 88 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_293{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {7d 30 0f b7 05 90 01 04 33 45 90 01 01 35 90 01 04 0f b7 0d 90 01 04 33 4d 90 01 01 81 f1 90 01 04 8b 15 90 01 04 8a 80 90 01 04 88 04 0a eb be 90 00 } //01 00 
		$a_03_1 = {eb 46 0f b7 05 90 01 04 83 c0 90 01 01 8b 0d 90 01 04 03 4d 90 01 01 0f be 11 33 d0 a1 90 01 04 03 45 90 01 01 88 10 eb 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_294{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 0d 6a 21 8b 55 e4 83 c2 28 ff d2 83 c4 04 e9 90 01 03 ff 90 00 } //02 00 
		$a_03_1 = {6a 40 68 00 30 00 00 68 c5 3e 00 00 6a 00 ff 15 c8 00 01 02 89 45 e4 c7 45 f0 00 00 00 00 8a 95 90 01 03 ff 88 95 90 01 03 ff 8b 8d 90 01 03 ff 90 02 30 8a 94 05 90 01 03 ff 33 ca 90 02 20 8b 55 e4 88 0c 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_295{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e0 04 03 c2 8b d1 03 4c 24 04 c1 ea 05 03 54 24 08 33 c2 33 c1 c3 } //01 00 
		$a_03_1 = {51 55 8b d0 8b cb e8 90 01 04 2b f8 59 59 8b cf 8b c7 c1 e9 05 03 4c 24 90 01 01 c1 e0 04 03 44 24 90 01 01 33 c8 8d 04 2f 33 c8 8b 44 24 90 01 01 2b d9 6a f7 59 2b c8 8b 44 24 90 01 01 03 e9 8b 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_296{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8d 14 06 e8 90 01 04 30 02 90 00 } //01 00 
		$a_03_1 = {7c ea 8b 1d 90 01 04 05 90 01 04 50 56 a3 90 01 04 ff d3 ff 35 90 01 04 a3 90 01 04 56 ff d3 8b d0 90 00 } //01 00 
		$a_03_2 = {03 45 fc 83 65 f4 00 a3 90 01 04 81 f3 90 01 04 81 6d f4 90 01 04 81 45 f4 90 01 04 8b 4d f4 d3 e8 5b 25 ff 7f 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_297{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 d0 31 f6 89 54 24 90 01 01 89 f2 f7 f1 8b 4c 24 90 01 01 8b 74 24 90 01 01 8b 7c 24 90 01 01 8a 1c 3e 2a 1c 15 90 01 04 8b 54 24 90 01 01 29 ca 8b 4c 24 90 01 01 88 1c 39 01 d7 90 00 } //01 00 
		$a_03_1 = {6a 00 ff d0 89 c1 90 09 10 00 8b 44 24 90 01 01 ff 74 24 90 01 01 ff 74 24 90 01 01 ff 74 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_298{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 05 50 ec 47 00 8b 1d 90 01 04 33 c6 33 c1 8a 90 01 05 41 81 f9 90 01 04 88 14 18 7c 90 00 } //01 00 
		$a_03_1 = {99 59 f7 f9 85 d2 74 17 66 81 3d 90 01 06 75 3b a1 90 01 04 03 c3 80 30 90 01 01 eb 90 00 } //01 00 
		$a_03_2 = {ff d5 8b c8 8b 44 24 90 01 01 33 d2 f7 f1 2c 90 01 01 30 06 43 81 fb 90 01 04 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_299{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 5a 1a 83 ea fc 03 5a 16 e2 f5 } //02 00 
		$a_01_1 = {73 16 8b 55 f8 03 55 fc 0f b6 02 83 f0 2b 8b 4d f8 03 4d fc 88 01 eb } //01 00 
		$a_03_2 = {50 8b 4d 08 8b 91 90 01 04 ff d2 90 00 } //01 00 
		$a_03_3 = {50 8b 4d fc 51 8b 55 08 8b 82 90 01 04 ff d0 90 00 } //01 00 
		$a_01_4 = {50 e8 00 00 00 00 58 05 ff 00 00 00 05 0e 01 00 00 ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_300{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {4f 0f b6 d8 8a 54 1c 90 01 01 0f b6 c2 03 c6 0f b6 f0 8a 44 34 90 01 01 88 44 1c 90 01 01 88 54 34 90 01 01 0f b6 4c 1c 90 01 01 0f b6 c2 03 c8 81 e1 90 01 04 79 08 49 81 c9 90 01 04 41 8a 4c 0c 90 01 01 30 4d 00 45 85 ff 75 90 00 } //01 00 
		$a_01_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 00 8b 40 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_301{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 8b 01 66 3d 4d 5a 75 f1 8b 59 3c 03 d9 66 8b 03 66 3d 50 45 75 e3 } //01 00 
		$a_01_1 = {c7 00 56 69 72 74 c7 40 04 75 61 6c 41 c7 40 08 6c 6c 6f 63 } //01 00 
		$a_03_2 = {03 d8 83 c3 90 01 01 0f b7 40 90 01 01 8b d0 c1 e2 90 01 01 8d 14 92 03 da 83 c3 90 01 01 8b 4b 90 01 01 03 4d 90 01 01 83 c1 90 01 01 8b 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_302{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 52 8b 85 90 01 04 8b 0c 85 90 01 04 89 8d 90 01 04 8b 95 90 01 04 2b 95 90 01 04 89 95 90 01 04 c1 85 90 01 04 0f 8b 85 90 01 04 33 05 90 01 04 89 85 90 01 04 8b 8d 90 01 04 8b 55 90 01 01 8b 85 90 01 04 89 04 8a eb 93 90 00 } //01 00 
		$a_03_1 = {c1 e1 06 51 8b 15 90 01 04 52 a1 90 01 04 50 6a 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_303{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 85 a4 df ff ff 25 ff 90 00 90 8b 4d fc 33 d2 8b 94 0d b4 d2 ff ff 33 c2 8b 4d fc 87 84 0d ac df ff ff 8b 55 fc 33 c0 8a 84 15 ac df ff ff 83 f8 3a 7f 19 8b 4d fc 33 d2 8a 94 0d ac df ff ff 83 ea 01 8b 45 fc 86 94 05 ac df ff ff } //01 00 
		$a_01_1 = {f6 c4 41 75 12 90 70 f8 27 41 6a 90 8d 95 d4 df ff ff ff d2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_304{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 35 8d 45 f8 50 6a 40 68 90 01 04 8b 45 08 50 ff 15 90 00 } //01 00 
		$a_03_1 = {8a 00 88 45 90 01 01 90 90 8b 45 90 01 01 89 45 90 01 01 80 75 90 01 01 d4 8b 45 90 01 01 03 45 90 01 01 73 05 e8 90 01 04 8a 55 90 01 01 88 10 90 00 } //01 00 
		$a_03_2 = {8b 45 08 05 4d 36 00 00 73 05 e8 90 01 04 89 45 90 01 01 ff 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_305{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 f4 66 c7 90 09 07 00 66 c7 90 01 03 00 00 90 00 } //01 00 
		$a_03_1 = {37 83 66 c7 90 09 07 00 66 c7 90 01 03 00 00 90 00 } //01 00 
		$a_03_2 = {04 31 66 c7 90 09 07 00 66 c7 90 01 03 00 00 90 00 } //01 00 
		$a_03_3 = {30 50 66 c7 90 09 07 00 66 c7 90 01 03 00 00 90 00 } //01 00 
		$a_03_4 = {24 b8 66 c7 90 09 07 00 66 c7 90 01 03 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_306{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 56 8b 7c 24 0c 8b 4c 24 10 8b 74 24 14 8b 54 24 18 85 d2 74 0e ac 52 30 07 5a 4a 47 e2 f3 5e 5b 33 c0 c3 } //01 00 
		$a_01_1 = {48 89 5c 24 08 57 48 83 ec 20 48 8b 41 10 48 8b f9 48 8b 00 48 3b 47 10 74 33 80 78 18 00 74 f1 48 8b 18 48 3b 47 10 74 1f 48 8b 48 08 48 89 19 48 8b 48 08 48 8b 10 48 89 4a 08 48 8b c8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_307{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 14 37 88 14 1e 83 fe 90 01 01 75 90 01 01 8d 45 f0 50 6a 90 01 01 68 90 01 04 53 ff 15 90 00 } //01 00 
		$a_03_1 = {8b d7 c1 ea 90 01 01 03 55 90 01 01 8b c7 c1 e0 90 01 01 03 45 90 01 01 8d 0c 3b 33 d0 33 d1 2b f2 8b d6 c1 ea 90 01 01 03 55 90 01 01 8b c6 c1 e0 90 01 01 03 45 90 01 01 8d 0c 33 33 d0 33 d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_308{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d8 8b 45 fc 69 c0 90 01 04 99 b9 90 01 04 f7 f9 88 9c 05 90 01 04 8b 45 fc 69 c0 90 01 04 99 b9 90 01 04 f7 f9 33 d2 8a 94 05 90 01 04 83 fa 90 00 } //01 00 
		$a_03_1 = {8b 45 fc 69 c0 90 01 04 99 b9 90 01 04 f7 f9 33 d2 8a 94 05 90 01 04 8b ca 83 e9 01 8b 45 fc 69 c0 90 01 04 99 be 90 01 04 f7 fe 88 8c 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_309{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 04 39 49 75 fa } //01 00 
		$a_03_1 = {6a 00 89 0c 90 01 01 33 c9 03 c8 8b f9 59 6a 00 89 04 90 01 01 33 c0 03 c7 89 83 90 01 04 58 6a 00 89 04 90 01 01 2b c0 0b 83 90 01 04 8b f0 58 6a 00 89 3c 90 01 01 33 ff 0b bb 90 01 04 8b cf 5f f3 a4 90 00 } //01 00 
		$a_01_2 = {52 59 03 cb 8b d1 59 23 d9 55 8b e8 33 eb 8b c5 5d ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_310{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8a 48 fc 88 4d f3 0f b6 55 f3 81 f2 90 01 01 00 00 00 52 8b 45 f8 50 68 34 c1 40 00 8b 4d f8 51 e8 90 01 03 ff 90 00 } //01 00 
		$a_03_1 = {6a 02 6a 01 8b 95 90 01 01 ff ff ff 52 ff 55 fc 89 85 90 00 } //01 00 
		$a_03_2 = {6a 00 6a 00 6a 24 6a 00 6a 00 6a 00 ff 95 90 01 02 ff ff 50 6a 00 ff 95 90 01 01 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_311{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 b9 04 00 00 00 f7 f1 8b 45 90 01 01 0f be 0c 10 8b 55 90 01 01 0f b6 82 90 01 04 33 c1 8b 4d 90 01 01 88 81 90 00 } //01 00 
		$a_03_1 = {8b 45 08 0f b6 08 89 4d 90 01 01 8b 55 90 01 01 89 55 90 01 01 8b 45 08 83 c0 01 89 45 08 83 7d 90 01 01 00 74 11 8b 4d 90 01 01 c1 e1 05 03 4d 90 01 01 03 4d 90 01 01 89 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_312{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f1 c1 ee 90 01 01 03 35 90 01 04 8b f9 c1 e7 90 01 01 03 3d 90 01 04 33 f7 8d 3c 0a 33 f7 2b c6 8b f0 c1 ee 90 01 01 03 35 90 01 04 8b f8 c1 e7 90 01 01 03 3d 90 01 04 33 f7 8d 3c 02 33 f7 2b ce 81 c2 90 01 04 ff 4d 90 01 01 75 b7 90 00 } //01 00 
		$a_03_1 = {8b c3 2b cb 8a 14 01 88 10 47 40 3b 7d 90 01 01 72 f4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_313{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 5f 89 bb 90 01 04 01 9b 90 01 04 01 9b 90 01 04 01 9b 90 01 04 8b b3 90 01 04 33 c9 83 bb ba 90 01 04 76 90 01 01 8b 8b 90 01 04 f3 a4 90 00 } //01 00 
		$a_03_1 = {03 fb 33 7d 0c 23 7d 08 2b 7d 90 01 01 3b 7d 0c 76 17 ff 93 90 01 04 ff 75 10 ff 75 0c e8 90 00 } //01 00 
		$a_01_2 = {33 d2 8b 5d 08 03 45 0c 23 45 08 0b 7d 08 03 c7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_314{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 c0 0b 07 83 ef 90 01 01 f7 d0 f8 83 d8 90 01 01 c1 c8 90 01 01 d1 c0 01 f0 8d 40 90 01 01 8d 30 c1 c6 90 01 01 d1 ce 50 8f 02 f8 83 da 90 01 01 83 c1 90 01 01 eb 90 00 } //01 00 
		$a_03_1 = {f7 de 51 8d 05 90 01 04 05 90 01 04 50 8d 0d 90 01 04 81 c1 90 01 04 51 8d 0d 90 01 04 81 c1 90 01 04 51 8d 05 90 01 04 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_315{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 0c 0f be 02 83 c8 90 01 01 0f b6 c8 33 4d 90 01 01 89 4d 90 01 01 8b 55 0c 83 c2 01 89 55 0c 90 00 } //01 00 
		$a_03_1 = {7d 26 8b 55 90 01 01 52 e8 90 01 04 83 c4 04 8b 4d 90 01 01 83 e1 01 8b 15 90 01 04 0f af 8a 84 00 00 00 33 c1 89 45 90 00 } //01 00 
		$a_03_2 = {8b 82 a4 01 00 00 ff d0 a3 90 01 04 a1 90 01 04 33 d2 f7 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_316{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 c0 02 c1 c0 04 c1 c0 04 33 05 90 01 04 c1 c0 03 03 05 90 01 04 03 05 90 01 04 c1 c0 03 c1 0d 90 01 04 06 ab 81 fe 90 01 04 7e 90 09 07 00 ad 2b 05 90 00 } //01 00 
		$a_03_1 = {c1 c0 03 03 05 90 01 04 c1 c0 04 03 05 90 01 04 c1 c0 04 03 05 90 01 04 c1 0d 90 01 04 06 ab 81 fe 90 01 04 7e 90 09 0d 00 ad 33 05 90 01 04 33 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_317{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 2a 8b 45 90 01 01 89 85 90 01 04 8b 4d 90 01 01 03 8d 90 01 04 8b 55 90 01 01 03 95 90 01 04 8a 02 88 01 8b 4d 90 01 01 83 c1 01 89 4d 90 01 01 eb 90 00 } //01 00 
		$a_03_1 = {8b 4d 08 8b 11 03 15 90 01 04 8b 45 08 89 10 90 00 } //01 00 
		$a_03_2 = {8b d2 8b c9 8b d2 ba 90 01 04 8b d2 89 55 90 01 01 8b d2 83 45 90 01 02 83 45 90 01 02 83 6d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_318{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e0 04 03 c2 8b d1 03 4c 24 90 01 01 c1 ea 05 03 54 24 90 01 01 33 c2 33 c1 90 00 } //01 00 
		$a_03_1 = {8b d0 8b cd e8 90 01 04 2b f8 59 59 8b cf 8b c7 c1 e9 90 01 01 03 4c 24 90 01 01 c1 e0 90 01 01 03 44 24 90 01 01 33 c8 8d 04 3b 33 c8 8b 44 24 90 01 01 2b e9 6a f7 59 2b c8 8b 44 24 90 01 01 03 d9 8b 4c 24 90 01 01 4e 75 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_319{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff ff ff 30 06 c3 } //01 00 
		$a_01_1 = {b8 fd 43 03 00 } //01 00 
		$a_01_2 = {b8 c3 9e 26 00 } //01 00 
		$a_01_3 = {b8 ff 7f 00 00 } //01 00 
		$a_03_4 = {8b c8 0f af 0d 90 01 04 e8 90 01 04 8d 54 01 01 89 15 90 01 04 e8 90 01 04 0f b7 0d 90 01 04 23 c1 c3 90 00 } //01 00 
		$a_03_5 = {8b c8 0f af 0d 90 01 04 e8 90 01 04 03 c8 89 0d 90 01 04 e8 90 01 04 0f b7 15 90 01 04 23 c2 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_320{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 33 d2 b9 0f 00 00 00 f7 f1 8a 86 90 01 04 8a 92 90 01 04 32 c2 88 86 90 01 04 46 81 fe 90 01 04 72 90 00 } //01 00 
		$a_00_1 = {32 1e 83 c6 04 88 5e 0c 8a 5e fd 32 5c 24 15 88 5e 0d 8a 5e fe 32 5c 24 16 88 5e 0e 8a 5e ff 32 d8 8b 44 24 10 88 5e 0f 40 41 } //01 00 
		$a_03_2 = {73 06 89 15 90 01 04 8b 35 90 01 04 8a 19 30 1c 30 47 41 40 4d 75 e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_321{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 04 24 b9 90 01 04 8b 54 24 90 01 01 d3 e2 89 54 24 90 01 01 8b 54 24 90 01 01 8a 0c 02 8b 74 24 90 01 01 88 0c 06 83 c0 01 8b 7c 24 90 01 01 39 f8 89 04 24 75 90 00 } //01 00 
		$a_03_1 = {31 d2 f7 f1 8a 1c 15 90 01 04 8b 4d 90 01 01 8b 55 90 01 01 8a 3c 11 28 df 8b 75 90 01 01 88 3c 16 83 c2 90 01 01 8b 7d 90 01 01 39 fa 89 55 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_322{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 11 8b 45 fc 03 45 90 01 01 0f b6 08 8d 54 11 02 8b 45 fc 03 45 90 01 01 88 10 8b 4d fc 03 4d 90 01 01 0f b6 11 83 ea 02 8b 45 fc 03 45 90 01 01 88 10 c7 45 f0 90 01 03 00 8b 4d f8 83 c1 01 89 4d f8 e9 43 ff ff ff 90 00 } //01 00 
		$a_01_1 = {8b 55 08 8b 02 03 45 fc 8b 4d 08 89 01 8b e5 5d c3 } //01 00 
		$a_03_2 = {8b ca 33 c1 90 02 30 89 11 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_323{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d7 8b d6 b9 90 01 04 e8 90 01 04 8b 0d 90 01 04 88 04 0e 46 3b 74 24 0c 72 90 00 } //01 00 
		$a_03_1 = {6a 00 ff 15 90 01 04 ff 15 90 01 04 8b cf 8b c7 c1 e9 05 03 4d 90 01 01 c1 e0 04 03 45 90 01 01 33 c8 8d 04 3e 33 c8 2b d9 8b cb 8b c3 c1 e9 05 03 4d 90 01 01 c1 e0 04 03 45 90 01 01 33 c8 8d 04 1e 33 c8 8d b6 90 01 04 2b f9 83 6d fc 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_324{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 0c c1 e0 90 01 01 03 45 10 8b 4d 0c 03 4d 18 33 c1 8b 55 0c c1 ea 90 01 01 03 55 14 33 c2 8b 4d 08 8b 11 2b d0 8b 45 08 89 10 90 00 } //01 00 
		$a_03_1 = {33 ca 8b 45 90 01 01 c1 e8 90 01 01 03 45 90 01 01 33 c8 8b 55 90 01 01 2b d1 89 55 90 01 01 8b 45 90 01 01 50 8b 4d 90 01 01 51 8b 55 90 01 01 52 8b 45 90 01 01 50 8d 4d 90 01 01 51 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_325{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {da 02 11 04 91 06 61 90 01 01 11 04 90 01 01 8e b7 5d 91 61 9c 11 04 17 d6 13 04 90 00 } //01 00 
		$a_01_1 = {67 65 74 5f 57 69 64 74 68 00 67 65 74 5f 48 65 69 67 68 74 00 47 65 74 50 69 78 65 6c 00 67 65 74 5f 52 00 67 65 74 5f 47 00 67 65 74 5f 42 } //01 00 
		$a_03_2 = {52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 90 02 20 2e 00 50 00 6e 00 67 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_326{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 0d a4 e4 90 01 02 a1 a0 e4 90 01 02 41 81 e1 ff 00 00 00 8b 3c 8d 90 90 b9 90 01 02 03 c7 25 ff 00 00 00 8a 14 85 90 90 b9 90 01 02 0f b6 d2 89 3c 85 90 90 b9 90 01 02 89 14 8d 90 90 b9 90 01 02 89 0d a4 e4 90 01 02 8b 0c 85 90 90 b9 90 01 02 03 ca 81 e1 ff 00 00 00 0f b6 14 8d 90 90 b9 90 01 02 a3 a0 e4 90 01 02 30 14 33 83 ee 01 79 9e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_327{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b ca 89 45 90 01 01 31 4d 90 01 01 8b 45 90 02 20 01 05 90 02 10 8b ff 8b 0d 90 01 04 8b 15 90 01 04 89 11 90 00 } //01 00 
		$a_03_1 = {8b 55 08 8b 02 03 45 90 01 01 8b 4d 08 89 01 90 00 } //01 00 
		$a_03_2 = {0f b6 08 8d 94 11 90 01 04 8b 45 90 01 01 03 45 90 01 01 88 10 8b 4d 90 01 01 03 4d 90 01 01 0f b6 11 81 ea 90 01 04 8b 45 90 01 01 03 45 90 01 01 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_328{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 89 85 90 01 04 8b 4d ec 03 8d 90 01 04 8b 55 f4 03 95 90 01 04 8a 02 88 01 8b 4d f8 83 c1 01 89 4d f8 eb 90 00 } //01 00 
		$a_03_1 = {89 45 f8 8b 0d 90 01 04 89 4d f8 8b 45 f8 31 45 fc 8b 55 fc 89 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 8b e5 90 00 } //01 00 
		$a_03_2 = {8b f6 ff 35 90 01 04 8b f6 33 d2 8d 05 90 01 04 48 03 10 8b c9 8b c9 8b c9 ff e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_329{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6b 00 66 c7 45 90 01 01 65 00 66 c7 45 90 01 01 72 00 66 c7 45 90 01 01 6e 00 66 c7 45 90 01 01 65 00 66 c7 45 90 01 01 6c 00 66 c7 45 90 01 01 33 00 66 c7 45 90 01 01 32 00 66 c7 45 90 01 01 2e 00 66 c7 45 90 01 01 64 00 66 c7 45 90 01 01 6c 00 66 c7 45 90 01 01 6c 00 66 c7 45 90 01 01 00 00 90 00 } //01 00 
		$a_01_1 = {8a 1c 30 80 f3 0e f6 d3 80 f3 cf 88 1c 30 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_330{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 57 08 8a 0d 90 01 04 8a 54 24 18 02 c1 8b 0d 90 01 04 32 c2 a2 90 01 04 88 04 19 8b 44 24 14 83 f8 10 75 90 00 } //01 00 
		$a_01_1 = {88 4d b8 88 45 c1 88 45 c2 c7 45 b9 70 70 68 65 c7 45 bd 6c 70 2e 64 c7 45 d8 47 65 74 50 c7 45 dc 65 72 6d 4c c7 45 e0 61 79 65 72 c6 45 e4 73 88 4d c8 c7 45 c9 74 6c 2e 64 88 45 cd 88 45 ce c7 45 e8 41 74 6c 41 c7 45 ec 64 76 69 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_331{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 00 72 00 69 00 6e 00 74 00 5f 00 73 00 63 00 72 00 65 00 65 00 6e 00 } //01 00  print_screen
		$a_01_1 = {8b fb b9 0a 00 00 00 8b c3 33 d2 f7 f1 89 c3 8b c3 03 c0 8d 04 80 2b f8 46 8b d7 80 c2 30 b8 14 00 00 00 2b c6 88 14 04 85 db 75 d4 } //01 00 
		$a_03_2 = {8b c1 83 e8 20 0f b7 d7 8b ca 33 d2 f7 f1 66 f7 ef 66 05 90 01 02 66 25 90 01 02 66 83 90 01 02 66 89 43 ea 83 c3 20 4e 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_332{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f0 8d bd 90 01 03 ff b9 10 00 00 00 f3 a5 90 00 } //01 00 
		$a_01_1 = {83 c4 08 8b f0 8d bd 04 ff ff ff b9 3e 00 00 00 f3 a5 } //01 00 
		$a_03_2 = {6a 40 68 00 30 00 00 8b 85 90 01 03 ff 50 6a 00 e8 90 01 03 ff 89 45 fc 90 00 } //01 00 
		$a_03_3 = {ff e0 6a 00 e8 90 01 03 ff 90 09 1e 00 8b 85 90 01 03 ff 2b 85 90 01 03 ff 3b 45 90 01 01 0f 82 90 01 03 ff 8b 45 fc 03 85 90 01 03 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_333{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 04 01 de 41 3b ca 72 f7 } //01 00 
		$a_03_1 = {6a 01 8d 3c 2e 53 53 57 68 90 01 04 53 ff 15 90 01 04 57 ff 15 90 01 04 8d 74 06 01 3b 74 24 20 72 90 00 } //01 00 
		$a_03_2 = {83 c4 10 68 90 01 04 ff 15 90 01 04 6a 0a ff 15 90 01 04 8b 54 24 90 01 01 8b 44 24 90 01 01 83 c2 10 83 c7 20 48 89 54 24 90 01 01 89 44 24 90 01 01 75 90 00 } //01 00 
		$a_01_3 = {45 58 45 5f 74 65 6d 70 25 78 25 73 } //00 00  EXE_temp%x%s
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_334{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 0f be 08 85 c9 74 50 8b 55 90 01 01 8b 4d 90 01 01 d3 ea b9 20 00 00 00 2b 4d 90 01 01 8b 45 90 01 01 d3 e0 0b d0 89 55 90 01 01 8b 4d 08 0f be 11 83 fa 61 7c 0e 90 00 } //01 00 
		$a_03_1 = {73 33 8b 4d 90 01 01 8b 55 90 01 01 8b 45 08 03 04 8a 50 e8 90 01 04 83 c4 04 3b 45 0c 75 17 8b 4d 90 01 01 8b 55 90 01 01 0f b7 04 4a 8b 4d 90 01 01 8b 55 08 03 14 81 8b c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_335{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6d 00 61 00 74 00 61 00 32 00 2e 00 62 00 61 00 74 00 90 02 20 64 00 61 00 73 00 69 00 6f 00 68 00 6e 00 64 00 61 00 73 00 64 00 61 00 73 00 64 00 90 00 } //01 00 
		$a_01_1 = {23 00 6e 00 65 00 77 00 74 00 6d 00 70 00 23 00 24 00 24 00 24 00 2e 00 65 00 78 00 65 00 24 00 24 00 24 00 } //01 00  #newtmp#$$$.exe$$$
		$a_01_2 = {66 00 73 00 66 00 73 00 64 00 66 00 73 00 64 00 66 00 73 00 64 00 66 00 73 00 64 00 66 00 } //00 00  fsfsdfsdfsdfsdf
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_336{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 45 fc 50 6a 40 68 90 01 03 00 8b 4d f4 51 ff 15 90 01 03 01 ff 55 f4 90 00 } //01 00 
		$a_03_1 = {8b 4d 0c 8b 11 89 55 90 01 01 8b 45 0c 8b 48 04 89 4d 90 01 01 8b 55 0c 8b 42 08 89 45 90 01 01 8b 4d 0c 8b 51 0c 90 00 } //01 00 
		$a_03_2 = {c1 e0 04 03 45 f8 8b 4d f4 03 4d f0 33 c1 8b 55 f4 c1 ea 05 03 55 90 01 01 33 c2 8b 4d 90 01 01 2b c8 89 4d 90 01 01 8b 55 f0 2b 55 90 01 01 89 55 f0 eb 9e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_337{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 2f 20 30 20 64 2f 20 44 52 4f 57 44 5f 47 45 52 20 74 2f 20 74 72 61 74 53 6f 74 75 41 64 65 79 61 6c 65 44 20 76 2f 20 22 72 65 76 72 65 73 6e 61 6d 6e 61 6c 5c 73 65 63 69 76 72 65 53 5c 74 65 53 6c 6f 72 74 6e 6f 43 74 6e 65 72 72 75 43 5c 4d 45 54 53 59 53 5c 45 4e 49 48 43 41 4d 5f 4c 41 43 4f 4c 5f 59 45 4b 48 22 20 64 64 61 20 67 65 72 } //01 00  f/ 0 d/ DROWD_GER t/ tratSotuAdeyaleD v/ "revresnamnal\secivreS\teSlortnoCtnerruC\METSYS\ENIHCAM_LACOL_YEKH" dda ger
		$a_00_1 = {66 6e 69 2e 72 65 76 69 72 44 } //00 00  fni.revirD
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_338{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 7e 08 89 56 04 c7 46 0c 04 00 00 00 c7 06 00 00 00 00 ff d0 } //01 00 
		$a_03_1 = {8b 44 24 50 8a 1c 15 90 01 04 35 90 01 04 8b 54 24 90 01 01 8a 3c 0a 8b 74 24 90 01 01 8b 7c 24 90 01 01 29 fe 28 df 89 74 24 90 01 01 8b 74 24 90 01 01 88 3c 0e 01 c1 90 00 } //01 00 
		$a_03_2 = {eb 00 8b 44 24 90 01 01 8b 4c 24 90 01 01 81 c1 90 01 04 8a 10 89 4c 24 90 01 01 8b 44 24 90 01 01 8b 4c 24 90 01 01 88 14 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_339{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 07 c1 e0 02 33 d2 8a 57 01 c1 ea 04 0a c2 8b 15 90 01 04 8b 0e 88 04 0a e8 90 01 04 ff 06 ff 05 90 01 04 4b 75 90 00 } //01 00 
		$a_03_1 = {75 34 8a 15 90 01 04 c1 e2 04 25 90 01 04 c1 e8 02 0a d0 a1 90 01 04 8b 0d 90 01 04 88 54 08 01 8b 15 90 01 04 83 c2 02 ff 05 90 01 04 8b c2 90 00 } //01 00 
		$a_03_2 = {33 db 8a da 83 fb 3d 7f 90 01 01 74 90 01 01 83 eb 2b 74 90 01 01 83 eb 04 74 90 01 01 4b 83 eb 0a 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_340{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {03 ca 8a 0c 01 8b 35 90 01 03 00 83 c6 03 0f af 75 90 01 01 03 75 90 01 01 88 0c 02 83 c0 01 3b 45 90 01 01 89 75 90 01 01 7c ce 90 00 } //02 00 
		$a_03_1 = {8b c6 2b c1 83 e8 04 0f af c7 8b 5d 90 01 01 8b 7d 90 01 01 83 c2 01 8d 48 03 0f af ca 8b 55 90 01 01 0f af ce 2b d9 8a 0c 17 32 cb 85 f6 74 05 88 0c 17 eb 03 88 14 17 90 00 } //01 00 
		$a_03_2 = {5f 5e 5b 8b e5 5d c2 10 00 90 09 05 00 8b 6d 90 01 01 ff d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_341{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 33 db 8a 14 01 b9 90 01 04 2b cf 0f af d1 8b 4e 90 01 01 8a 1c 01 8b 4e 90 01 01 0f af df 03 d3 c1 ea 90 01 01 88 14 08 40 3d 90 01 04 7c 90 00 } //01 00 
		$a_01_1 = {8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10 } //01 00 
		$a_03_2 = {88 45 fa 88 45 fb c6 45 90 09 20 00 c6 45 90 01 01 4b c6 45 90 01 01 52 c6 45 90 01 01 4e c6 45 90 01 01 4c c6 45 90 01 01 33 c6 45 90 01 01 32 c6 45 90 01 01 2e c6 45 90 01 01 64 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_342{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {29 c0 33 01 83 c1 04 f7 d0 f8 83 d8 90 01 01 c1 c8 90 01 01 d1 c0 01 f8 8d 40 90 01 01 31 ff 4f 21 c7 c1 c7 90 01 01 d1 cf 50 8f 06 90 00 } //01 00 
		$a_03_1 = {50 29 c0 8d 80 90 01 04 83 c0 01 8f 00 68 90 01 04 82 04 24 04 ff 35 90 01 04 8d 05 90 01 04 ff 10 90 00 } //01 00 
		$a_03_2 = {f7 da 51 52 ba 90 01 04 81 ea 90 01 04 52 be 90 01 04 81 ee 90 01 04 56 b8 90 01 04 2d 90 01 04 50 b8 90 01 04 50 b8 90 01 04 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_343{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 00 c1 e8 0c 83 f8 03 75 28 8b 85 90 01 04 8b 00 8b 7d 90 01 01 03 c7 8b 95 90 01 04 66 8b 12 66 81 e2 90 01 02 0f b7 d2 03 c2 2b bd 90 01 04 01 38 90 00 } //01 00 
		$a_03_1 = {8b f2 8b c1 8b 55 90 01 01 8b 14 b2 8b 4d 90 01 01 89 14 99 8b 55 90 01 01 89 04 b2 8b 45 90 01 01 8b 04 98 8b 55 90 01 01 03 04 b2 b9 90 01 04 99 f7 f9 8b 45 90 01 01 8b 14 90 90 8b 45 90 01 01 8b 4d 90 01 01 0f b6 44 08 ff 33 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_344{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 11 8b 45 90 01 01 03 45 90 01 01 0f b6 08 03 d1 81 e2 90 01 04 79 90 09 09 00 83 c4 90 01 01 8b 4d 90 01 01 03 4d 90 00 } //01 00 
		$a_03_1 = {8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 90 01 04 83 f9 90 01 01 0f 82 90 01 04 81 f9 90 01 04 73 13 0f ba 25 90 01 04 01 0f 82 90 01 04 e9 90 01 04 0f ba 25 90 01 04 01 73 09 f3 a4 90 00 } //01 00 
		$a_03_2 = {8b 06 03 d0 83 f0 90 01 01 33 c2 8b 16 83 c6 04 a9 90 01 04 74 dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_345{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f1 c1 ee 90 01 01 03 35 90 01 04 8b f9 c1 e7 90 01 01 03 3d 90 01 04 33 f7 8d 3c 0a 33 f7 2b c6 8b f0 c1 ee 90 01 01 03 35 90 01 04 8b f8 c1 e7 90 01 01 03 3d 90 01 04 33 f7 8d 3c 02 33 f7 2b ce 81 c2 90 00 } //01 00 
		$a_03_1 = {6a 00 ff 15 90 01 04 8a 8e 90 01 04 8b 15 90 01 04 88 0c 32 ff d7 46 3b 75 fc 90 00 } //01 00 
		$a_03_2 = {8b 55 fc 8d 4d f8 51 8b 0d 90 01 04 6a 40 52 51 ff d0 8b 45 fc 8b 35 90 01 04 c1 e8 03 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_346{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 0f 8b c1 33 d2 5f f7 f7 8a 82 90 01 04 30 81 90 01 04 41 3b ce 72 e6 90 00 } //01 00 
		$a_03_1 = {73 09 8b 4d fc 89 0d 90 01 04 8b 0d 90 01 04 8a 18 30 1c 31 03 ce 47 40 46 4a 75 90 00 } //01 00 
		$a_03_2 = {0f b6 4c 24 04 8b c1 03 c9 c1 e8 90 01 01 6b c0 90 01 01 33 c1 c3 90 00 } //01 00 
		$a_03_3 = {57 32 d8 e8 90 01 04 32 d8 a1 90 01 04 32 5d 90 01 01 83 c4 20 32 5d 90 01 01 32 5d 90 01 01 88 1c 06 8b 45 90 01 01 80 b8 90 01 04 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_347{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 8d 8f fc ff ff 33 8d 88 fc ff ff 88 8d 87 fc ff ff 8b 95 ec fd ff ff 03 55 10 8b 85 94 fc ff ff 2b 85 ec fd ff ff 03 95 cc fc ff ff 8d 8c 82 b9 00 00 00 89 8d cc fc ff ff 8b 95 cc fc ff ff 83 c2 08 39 95 ec fd ff ff 75 17 8b 85 88 fc ff ff 2b 45 10 8b 8d cc fc ff ff 2b c8 89 8d cc fc ff ff 8b 95 ac fc ff ff 03 15 40 91 45 00 03 15 4c 91 45 00 03 15 40 91 45 00 89 15 40 91 45 00 8a 85 87 fc ff ff 88 85 90 fc ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_348{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 fc 0f be 1a e8 90 01 03 ff 33 d8 8b 45 08 03 45 fc 88 18 eb c7 90 00 } //01 00 
		$a_03_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 90 01 03 00 a1 90 01 03 00 c1 e8 10 25 ff 7f 00 00 5d c3 90 00 } //01 00 
		$a_03_2 = {50 6a 00 ff 15 90 01 03 00 a3 90 01 03 00 68 90 01 03 00 6a 40 8b 8d 90 01 02 ff ff 51 8b 15 90 01 03 00 52 ff 15 90 01 03 00 a1 90 01 03 00 03 85 90 01 02 ff ff 8b 4d 90 01 01 03 8d 90 01 02 ff ff 8a 11 88 10 eb 91 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_349{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 79 00 73 00 74 00 65 00 6d 00 20 00 68 00 61 00 6c 00 74 00 65 00 64 00 } //01 00  System halted
		$a_01_1 = {56 65 72 69 66 69 63 61 74 6f 72 00 62 6c 75 72 00 62 00 } //01 00 
		$a_01_2 = {45 00 78 00 69 00 73 00 74 00 73 00 20 00 69 00 6e 00 20 00 74 00 68 00 65 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 20 00 64 00 69 00 72 00 20 00 6f 00 66 00 20 00 74 00 68 00 65 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 } //01 00  Exists in the current dir of the system
		$a_01_3 = {07 91 06 61 d2 9c 07 17 58 0b } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_350{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 ca 8b 45 90 01 01 c1 e0 19 c1 f8 1f 23 45 90 01 01 33 c8 8b 55 90 01 01 c1 e2 18 c1 fa 1f 23 55 90 01 01 33 ca 89 4d 90 01 01 8b 45 90 01 01 c1 e8 08 33 45 90 01 01 89 45 90 00 } //01 00 
		$a_03_1 = {c1 e2 1e c1 fa 1f 23 55 90 01 01 33 ca 8b 45 90 01 01 c1 e0 1d c1 f8 1f 23 45 90 01 01 33 c8 8b 55 90 01 01 c1 e2 1c c1 fa 1f 23 55 90 01 01 33 ca 8b 45 90 01 01 c1 e0 1b c1 f8 1f 23 45 90 01 01 33 c8 8b 55 90 01 01 c1 e2 1a c1 fa 1f 23 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_351{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 c6 01 d6 81 c6 90 01 04 8b 16 8b 74 24 90 01 01 69 f9 90 01 04 01 f8 05 90 01 04 33 10 01 f2 89 54 24 90 00 } //02 00 
		$a_03_1 = {89 c6 01 d6 81 c6 90 01 04 69 d1 90 01 04 01 d0 05 90 01 04 8b 00 33 06 03 44 24 90 01 01 89 44 24 90 00 } //01 00 
		$a_03_2 = {89 c8 31 d2 8b 74 24 90 01 01 f7 f6 8b 7c 24 90 01 01 8a 1c 0f 2a 1c 15 90 01 04 8b 54 24 90 01 01 88 1c 0a 90 00 } //01 00 
		$a_03_3 = {8a 14 01 8b 74 24 90 01 01 8a b6 90 01 04 28 f2 8b 74 24 90 01 01 88 14 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_352{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 72 0c 89 4a 04 c7 42 08 00 10 00 00 c7 02 00 00 00 00 ff d0 } //01 00 
		$a_03_1 = {74 d9 8b 44 24 90 01 01 8b 4c 24 90 01 01 83 f1 90 01 01 8b 54 24 90 01 01 8a 1c 02 89 4c 24 90 01 01 8b 4c 24 90 01 01 88 1c 01 83 c0 01 89 44 24 90 01 01 8b 74 24 90 01 01 39 f0 90 00 } //01 00 
		$a_03_2 = {89 fa f7 f1 8b 4c 24 90 01 01 8b 7c 24 90 01 01 89 7c 24 90 01 01 8b 7c 24 90 01 01 29 cf 8a 1c 15 90 01 04 8b 4c 24 90 01 01 8a 3c 31 28 df 8b 54 24 90 01 01 88 3c 32 01 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_353{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 ec 49 c6 45 ed 73 c6 45 ee 42 c6 45 ef 61 c6 45 f0 64 c6 45 f1 43 c6 45 f2 6f c6 45 f3 64 c6 45 f4 65 c6 45 f5 50 c6 45 f6 74 c6 45 f7 72 c6 45 f8 00 } //01 00 
		$a_01_1 = {c6 45 d4 51 c6 45 d5 75 c6 45 d6 65 c6 45 d7 72 c6 45 d8 79 c6 45 d9 50 c6 45 da 65 c6 45 db 72 c6 45 dc 66 c6 45 dd 6f c6 45 de 72 c6 45 df 6d c6 45 e0 61 c6 45 e1 6e c6 45 e2 63 c6 45 e3 65 c6 45 e4 43 c6 45 e5 6f c6 45 e6 75 c6 45 e7 6e c6 45 e8 74 c6 45 e9 65 c6 45 ea 72 c6 45 eb 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_354{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 8b 55 90 01 01 8b 42 54 50 8b 4d 08 51 8b 90 02 05 52 8b 85 90 01 04 50 ff 95 90 00 } //01 00 
		$a_03_1 = {8b 55 08 03 51 3c 03 55 90 01 01 8b 90 02 05 0f af 45 90 01 01 03 d0 89 95 90 00 } //02 00 
		$a_03_2 = {6a 00 8b 85 90 01 04 8b 48 10 51 8b 95 90 01 04 8b 45 08 03 42 14 50 8b 8d 90 01 04 8b 90 02 05 03 51 0c 52 8b 85 90 01 04 50 ff 95 90 00 } //02 00 
		$a_03_3 = {6a 00 6a 04 8b 55 90 01 01 83 c2 34 52 8b 45 90 01 01 8b 88 a4 00 00 00 83 c1 08 51 8b 95 90 01 04 52 ff 95 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_355{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 52 8b 85 90 01 04 8b 0c 85 90 01 04 89 8d 90 01 04 8b 95 90 01 04 2b 95 90 01 04 89 95 90 01 04 c1 85 90 01 04 0f 8b 85 90 01 04 33 05 90 01 04 89 85 90 01 04 8b 8d 90 01 04 8b 55 90 01 01 8b 85 90 01 04 89 04 8a eb 93 90 00 } //01 00 
		$a_03_1 = {73 52 8b 8d 90 01 04 8b 14 8d 90 01 04 89 95 90 01 04 8b 85 90 01 04 2b 85 90 01 04 89 85 90 01 04 c1 85 90 01 04 0f 8b 8d 90 01 04 33 0d 90 01 04 89 8d 90 01 04 8b 95 90 01 04 8b 45 90 01 01 8b 8d 90 01 04 89 0c 90 90 eb 93 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_356{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8e b7 5d 91 11 04 d6 13 04 11 04 1b d6 11 05 20 ff 00 00 00 5f d8 11 05 1e 63 d6 13 05 11 04 1d d6 90 01 01 20 ff 00 00 00 5f d8 90 01 01 1e 63 d6 90 01 01 11 05 1e 62 90 01 01 d6 20 ff 00 00 00 5f 13 04 90 01 01 11 07 02 11 07 91 11 04 b4 28 90 01 04 28 90 01 04 9c 11 07 17 d6 13 07 90 00 } //01 00 
		$a_03_1 = {8e b7 5d 91 09 d6 0d 09 1b d6 08 20 ff 00 00 00 5f d8 08 1e 63 d6 0c 09 1d d6 06 20 ff 00 00 00 5f d8 06 1e 63 d6 0a 08 1e 62 06 d6 20 ff 00 00 00 5f 0d 11 04 11 07 02 11 07 91 09 b4 28 90 01 04 28 90 01 04 9c 11 07 17 d6 13 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_357{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {ff ff ff 24 03 00 00 73 52 8b 90 01 02 ff ff ff 8b 90 01 04 41 00 89 90 01 02 ff ff ff 8b 90 01 02 ff ff ff 2b 90 01 02 ff ff ff 89 90 01 02 ff ff ff c1 85 90 01 01 ff ff ff 0f 8b 90 01 02 ff ff ff 33 90 01 03 41 00 89 90 01 02 ff ff ff 8b 90 01 02 ff ff ff 8b 90 01 02 8b 90 01 02 ff ff ff 89 90 01 02 eb 93 90 00 } //02 00 
		$a_03_1 = {24 03 00 00 73 33 8b 45 90 01 01 8b 4d 90 01 01 8b 14 81 89 55 90 01 01 8b 45 90 01 01 2b 45 90 01 01 89 45 90 01 01 c1 45 90 01 01 0f 8b 4d 90 01 01 33 0d 90 01 04 89 4d 90 01 01 8b 55 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 89 0c 90 90 eb bb 90 00 } //01 00 
		$a_01_2 = {68 b8 88 00 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_358{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 00 73 00 73 00 77 00 3d 00 28 00 28 00 } //01 00  ossw=((
		$a_01_1 = {20 44 77 6e 6c 64 46 69 6c 65 } //01 00   DwnldFile
		$a_03_2 = {43 4d 44 00 90 02 30 44 4c 4c 90 02 30 4e 4f 50 90 00 } //01 00 
		$a_01_3 = {3c 00 68 00 74 00 6d 00 6c 00 3e 00 3c 00 68 00 65 00 61 00 64 00 3e 00 3c 00 74 00 69 00 74 00 6c 00 65 00 3e 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 20 00 49 00 50 00 20 00 43 00 68 00 65 00 63 00 6b 00 3c 00 2f 00 74 00 69 00 74 00 6c 00 65 00 3e 00 3c 00 2f 00 68 00 65 00 61 00 64 00 3e 00 3c 00 62 00 6f 00 64 00 79 00 3e 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 20 00 49 00 50 00 20 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 } //01 00  <html><head><title>Current IP Check</title></head><body>Current IP Address
		$a_01_4 = {06 07 8f 26 00 00 01 25 49 1d 61 d1 53 07 17 58 0b } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_359{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 00 47 00 39 00 68 00 5a 00 41 00 3d 00 3d 00 } //01 00  TG9hZA==
		$a_01_1 = {51 00 32 00 46 00 73 00 62 00 45 00 4a 00 35 00 54 00 6d 00 46 00 74 00 5a 00 51 00 3d 00 3d 00 } //01 00  Q2FsbEJ5TmFtZQ==
		$a_01_2 = {52 00 32 00 56 00 30 00 54 00 32 00 4a 00 71 00 5a 00 57 00 4e 00 30 00 56 00 6d 00 46 00 73 00 64 00 57 00 55 00 3d 00 } //01 00  R2V0T2JqZWN0VmFsdWU=
		$a_01_3 = {50 6f 73 74 5f 4d 61 72 6b 4d 61 69 6c 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //02 00  Post_MarkMail.Resources.resources
		$a_03_4 = {53 00 74 00 61 00 72 00 74 00 75 00 70 00 46 00 69 00 6c 00 65 00 90 02 10 52 00 75 00 6e 00 4f 00 6e 00 52 00 65 00 62 00 6f 00 6f 00 74 00 90 00 } //02 00 
		$a_03_5 = {48 00 69 00 64 00 64 00 65 00 6e 00 41 00 74 00 72 00 69 00 62 00 90 02 10 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 24 00 90 00 } //02 00 
		$a_03_6 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 49 00 90 02 10 41 00 6e 00 74 00 69 00 73 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 90 00 } //02 00 
		$a_03_7 = {42 00 79 00 70 00 61 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 90 02 10 53 00 74 00 61 00 72 00 74 00 42 00 6f 00 74 00 4b 00 69 00 6c 00 6c 00 65 00 72 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#MpRequestHookwowM_360{
	meta:
		description = "!#MpRequestHookwowM,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d fc c1 e1 04 03 4d ec 8b 55 fc 03 55 f4 33 ca 8b 45 fc c1 e8 05 03 45 e8 33 c8 8b 55 f8 2b d1 89 55 f8 8b 45 f8 c1 e0 04 03 45 e4 8b 4d f8 03 4d f4 33 c1 8b 55 f8 c1 ea 05 03 55 e0 33 c2 8b 4d fc 2b c8 89 4d fc 8b 55 f4 2b 55 dc 89 55 f4 } //00 00 
	condition:
		any of ($a_*)
 
}