
rule Trojan_BAT_AgentTesla_VN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 0a 06 16 7e 90 01 03 04 a2 06 17 7e 90 01 03 04 a2 06 18 72 90 01 03 70 a2 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 25 16 7e 90 01 03 04 a2 25 17 02 7b 90 01 03 04 a2 25 18 72 90 01 03 70 a2 0a 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 02 19 8d 90 01 03 01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 72 90 01 03 70 a2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 25 16 28 90 01 03 06 9d 25 17 28 90 01 03 06 9d 25 18 1f 90 01 01 9d 25 19 1f 90 01 01 9d 80 90 01 03 04 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 06 19 8d 90 01 03 01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 72 90 01 03 70 a2 28 90 01 03 0a 26 16 0b 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 9a 0a 06 14 19 8d 90 01 03 01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 72 90 01 03 70 a2 0b 07 6f 90 01 03 0a 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_7{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 90 01 01 02 07 8f 90 01 03 01 25 71 90 01 03 01 06 07 1f 90 01 01 5d 91 61 d2 81 90 01 03 01 07 17 58 0b 07 02 8e 69 32 90 01 01 02 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_8{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0b 16 0b 2b 90 01 01 02 07 8f 90 01 03 01 25 71 90 01 03 01 06 07 1f 90 01 01 5d 91 61 d2 81 90 01 03 01 07 17 58 0b 07 02 8e 69 fe 90 01 01 0d 09 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_9{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 07 19 8d 90 01 03 01 80 90 01 03 04 7e 90 01 03 04 16 7e 90 01 03 04 a2 7e 90 01 03 04 17 7e 90 01 03 04 a2 02 11 06 28 90 01 03 06 7e 90 01 03 04 28 90 01 03 06 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_10{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {5f 9c 61 1f 90 01 01 59 06 61 90 09 29 00 0e 90 01 01 05 7e 90 01 03 04 20 90 01 03 00 7e 90 01 03 04 20 90 01 03 00 91 7e 90 01 03 04 20 90 01 03 00 91 5f 20 90 01 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_11{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 25 16 72 90 01 03 70 a2 25 17 7e 90 01 03 04 a2 25 18 7e 90 01 03 04 a2 13 90 01 01 11 90 01 01 28 90 01 03 0a 00 11 90 01 01 73 90 01 03 06 13 90 01 01 2b 90 09 05 00 19 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_12{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 02 16 28 90 01 03 0a 02 7b 90 01 03 04 16 7e 90 01 03 04 a2 02 7b 90 01 03 04 17 7e 90 01 03 04 a2 02 7b 90 01 03 04 18 20 90 01 04 28 90 01 03 06 a2 02 7b 90 01 03 04 73 90 01 03 06 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_13{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 72 90 01 03 70 17 18 8d 90 01 03 01 25 17 18 8d 90 01 03 01 25 16 7e 90 01 03 04 a2 25 17 72 90 01 03 70 a2 a2 28 90 01 03 0a 26 16 28 90 01 03 0a 00 72 90 01 03 70 13 90 01 01 2b 90 01 01 11 90 01 01 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_14{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 20 90 01 04 28 90 01 03 06 a2 0a 90 00 } //01 00 
		$a_03_1 = {01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 20 90 01 04 28 90 01 03 06 a2 80 90 01 03 04 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_15{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 0a 06 16 7e 90 01 03 04 a2 06 17 7e 90 01 03 04 a2 06 18 72 90 01 03 70 a2 06 73 90 01 03 06 0b 2a 90 00 } //01 00 
		$a_03_1 = {01 0b 07 16 7e 90 01 03 04 a2 07 17 7e 90 01 03 04 a2 07 18 72 90 01 03 70 a2 07 73 90 01 03 06 0c 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_16{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 25 16 02 28 90 01 03 06 a2 25 17 02 28 90 01 03 06 a2 25 18 72 90 01 03 70 a2 0a 06 73 90 01 03 06 0b 2b 90 00 } //01 00 
		$a_03_1 = {01 25 16 28 90 01 03 06 a2 25 17 28 90 01 03 06 a2 25 18 72 90 01 03 70 a2 0a 06 73 90 01 03 06 0b 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_17{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {5d 91 61 d2 81 90 01 03 01 00 06 17 13 90 01 01 20 90 01 04 20 90 01 04 20 90 01 04 61 20 90 01 04 40 90 01 03 00 20 90 01 03 00 13 90 01 01 20 90 01 04 58 00 58 0a 06 02 8e 69 fe 90 01 01 0c 08 2d 90 01 01 02 0b 2b 90 01 01 07 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_18{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 06 02 8e 69 5d 02 06 02 8e 69 5d 91 03 06 03 8e 69 5d 91 61 28 90 01 03 0a 02 06 17 58 02 8e 69 5d 91 28 90 01 03 0a 59 20 90 01 03 00 58 20 90 01 03 00 5d 28 90 01 03 0a 9c 00 06 15 58 0a 06 16 fe 90 01 01 16 fe 90 01 01 0b 07 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_19{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0b 16 0b 2b 90 01 01 02 07 8f 90 01 03 01 25 71 90 01 03 01 06 07 00 23 90 02 0a 23 90 02 0a 28 90 01 03 0a 58 28 90 01 03 0a 5d 91 61 d2 81 90 01 03 01 07 17 58 0b 07 02 8e 69 fe 90 01 01 0d 09 2d 90 01 01 02 0c 2b 90 01 01 08 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_20{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0b 16 0b 2b 90 01 01 02 07 8f 90 01 03 01 25 71 90 01 03 01 06 07 00 23 90 02 0a 23 90 02 0a 28 90 01 03 0a 59 28 90 01 03 0a 5d 91 61 d2 81 90 01 03 01 07 17 58 0b 07 02 8e 69 fe 90 01 01 0d 09 2d 90 01 01 02 0c 2b 90 01 01 08 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_21{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 02 19 8d 90 01 03 01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 20 90 01 04 28 90 01 03 06 a2 90 00 } //01 00 
		$a_03_1 = {04 02 19 8d 90 01 03 01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 20 90 01 04 28 90 01 03 2b a2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_22{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 0a 06 16 72 90 01 03 70 a2 06 17 7e 90 01 03 04 a2 06 18 7e 90 01 03 04 a2 06 28 90 01 03 0a 00 06 90 00 } //01 00 
		$a_03_1 = {0a 06 16 02 7b 90 01 03 04 6f 90 01 03 0a a2 06 17 7e 90 01 03 04 a2 06 18 7e 90 01 03 04 a2 06 28 90 01 03 0a 00 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_23{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 0a 06 16 7e 90 01 03 04 a2 06 17 7e 90 01 03 04 a2 06 18 20 90 01 04 28 90 01 03 06 a2 7e 90 01 03 04 28 90 01 03 06 0b 02 07 90 00 } //01 00 
		$a_03_1 = {01 0a 06 16 7e 90 01 03 04 a2 06 17 7e 90 01 03 04 a2 06 18 20 90 01 04 28 90 01 03 2b a2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_24{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 0a 06 16 7e 90 01 03 04 a2 06 17 7e 90 01 03 04 a2 06 18 72 90 01 03 70 a2 06 73 90 01 03 06 0b 90 00 } //01 00 
		$a_03_1 = {01 25 16 7e 90 01 03 04 a2 80 90 01 03 04 2a 90 09 19 00 72 90 01 03 70 80 90 01 03 04 72 90 01 03 70 80 90 01 03 04 19 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_25{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 06 19 8d 90 01 03 01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 72 90 01 03 70 a2 28 90 01 03 0a 26 16 28 90 01 03 0a 00 16 0b 2b 90 01 01 07 2a 90 09 1f 00 02 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_26{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 6f 6f 64 6c 65 45 61 74 } //01 00  DoodleEat
		$a_81_1 = {44 6f 6f 64 6c 65 47 68 6f 73 74 } //01 00  DoodleGhost
		$a_81_2 = {52 65 61 64 42 79 74 65 } //01 00  ReadByte
		$a_81_3 = {42 6c 6f 63 6b 43 6f 70 79 } //01 00  BlockCopy
		$a_81_4 = {57 72 69 74 65 } //01 00  Write
		$a_81_5 = {24 30 32 30 38 46 32 45 31 2d 43 32 33 41 2d 34 35 34 42 2d 41 44 39 36 2d 37 30 39 42 33 34 35 38 38 36 33 38 } //00 00  $0208F2E1-C23A-454B-AD96-709B34588638
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_27{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 16 13 90 01 01 2b 90 01 01 03 11 90 01 01 18 6f 90 01 03 0a 1f 90 01 01 28 90 01 03 0a 08 09 91 61 d1 13 90 01 01 06 11 90 01 01 6f 90 01 03 0a 26 09 04 6f 90 01 03 0a 17 59 33 90 01 01 16 0d 2b 90 01 01 09 17 58 0d 11 90 01 01 18 58 13 90 01 01 11 90 01 01 03 6f 90 01 03 0a 17 59 31 90 01 01 06 6f 90 01 03 0a 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_28{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 65 74 46 75 6c 6c 50 61 74 68 } //01 00  GetFullPath
		$a_81_1 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_81_2 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //01 00  WriteAllBytes
		$a_81_3 = {57 72 69 74 65 } //01 00  Write
		$a_81_4 = {42 6c 6f 63 6b 43 6f 70 79 } //01 00  BlockCopy
		$a_81_5 = {24 64 35 30 36 39 37 31 37 2d 32 37 31 37 2d 34 63 63 35 2d 38 34 64 32 2d 64 38 37 35 38 32 34 30 30 66 65 34 } //00 00  $d5069717-2717-4cc5-84d2-d87582400fe4
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_29{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 69 6e 69 5f 47 61 6d 65 5f 43 65 6e 74 65 72 2e 4d 79 } //01 00  Mini_Game_Center.My
		$a_81_1 = {73 6e 61 6b 65 47 61 6d 65 4f 76 65 72 } //01 00  snakeGameOver
		$a_81_2 = {4d 69 6e 69 5f 47 61 6d 65 5f 43 65 6e 74 65 72 2e 73 6e 61 6b 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Mini_Game_Center.snake.resources
		$a_81_3 = {24 37 31 38 30 62 38 61 34 2d 62 31 64 65 2d 34 37 35 39 2d 62 33 39 64 2d 33 32 64 35 65 65 32 37 36 34 30 38 } //00 00  $7180b8a4-b1de-4759-b39d-32d5ee276408
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_30{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 25 06 1f 90 01 01 6f 90 01 03 0a 6f 90 01 03 0a 00 25 06 1f 90 01 01 6f 90 01 03 0a 6f 90 01 03 0a 00 6f 90 01 03 0a 03 16 03 8e 69 6f 90 01 03 0a 0b 00 07 8e 69 1f 90 01 01 da 17 d6 8d 90 01 03 01 0c 07 1f 90 01 01 08 16 07 8e 69 1f 90 01 01 da 28 90 01 03 0a 00 08 0d 2b 90 01 01 09 2a 90 09 13 00 00 04 1e 8d 90 01 03 01 17 73 90 01 03 0a 0a 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_31{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 16 0b 38 90 01 03 00 02 07 8f 90 01 03 01 25 71 90 01 03 01 06 07 20 90 01 04 fe 90 01 03 fe 90 01 03 fe 90 01 03 fe 90 01 03 fe 90 01 03 58 20 90 01 04 fe 90 01 01 3a 90 01 03 00 00 20 90 01 03 00 fe 90 01 03 00 38 90 01 03 00 00 20 90 01 04 28 90 01 03 06 fe 90 01 03 00 11 90 01 01 5d 91 61 d2 81 90 01 03 01 07 17 58 0b 07 02 8e 69 fe 90 01 01 0d 09 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_32{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 61 74 68 44 72 69 6c 6c 5f 30 31 2e 4d 79 } //01 00  MathDrill_01.My
		$a_81_1 = {73 74 61 72 74 47 61 6d 65 } //01 00  startGame
		$a_81_2 = {67 61 6d 65 4f 76 65 72 } //01 00  gameOver
		$a_01_3 = {4d 00 61 00 74 00 68 00 44 00 72 00 69 00 6c 00 6c 00 5f 00 30 00 31 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  MathDrill_01.Resources
		$a_81_4 = {24 34 45 34 38 46 30 41 41 2d 38 44 38 46 2d 34 36 44 36 2d 41 44 31 36 2d 37 37 33 42 46 33 43 39 42 36 31 39 } //00 00  $4E48F0AA-8D8F-46D6-AD16-773BF3C9B619
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_33{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {58 00 0b 2b 90 01 01 02 07 8f 90 01 03 01 25 71 90 01 03 01 06 07 1f 90 01 01 13 90 01 01 20 90 01 04 20 90 01 04 20 90 01 04 61 20 90 01 04 40 90 01 03 00 20 90 01 03 00 13 90 01 01 20 90 01 04 58 00 5d 91 61 d2 81 90 01 03 01 07 17 13 90 01 01 20 90 01 04 20 90 01 04 20 90 01 04 61 20 90 01 04 40 90 01 03 00 20 90 01 03 00 13 90 01 01 20 90 01 04 58 00 58 0b 07 02 8e 69 fe 90 01 01 0d 09 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VN_MTB_34{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 0a 02 28 90 01 03 06 06 6f 90 01 03 0a 0b 07 14 02 72 90 01 03 70 28 90 01 03 06 17 8d 90 01 03 01 25 16 72 90 01 03 70 a2 14 14 28 90 01 03 0a 0c 08 14 02 72 90 01 03 70 28 90 01 03 06 17 8d 90 01 03 01 25 16 72 90 01 03 70 a2 14 14 28 90 01 03 0a 0d 09 14 02 72 90 01 03 70 28 90 01 03 06 18 8d 90 01 03 01 25 17 18 8d 90 01 03 01 25 16 7e 90 01 03 04 a2 25 17 72 90 01 03 70 a2 a2 14 14 28 90 01 03 0a 26 72 90 01 03 70 13 90 01 01 2b 90 01 01 11 90 01 01 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}