
rule TrojanDropper_MacOS_UpdateAgent_C_MTB{
	meta:
		description = "TrojanDropper:MacOS/UpdateAgent.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 44 46 43 72 65 61 74 6f 72 2f 6d 61 69 6e 2e 73 77 69 66 74 } //01 00  PDFCreator/main.swift
		$a_00_1 = {4c 89 a5 70 ff ff ff 48 89 75 d8 48 89 7d d0 31 ff e8 15 1a 00 00 48 89 45 80 48 8b 40 f8 48 89 85 78 ff ff ff 48 8b 40 40 48 89 e1 48 83 c0 0f 48 83 e0 f0 48 29 c1 48 89 4d 88 48 89 cc 31 ff e8 40 1a 00 00 48 89 45 98 48 8b 40 f8 48 89 45 a0 48 8b 40 40 49 89 e6 48 83 c0 0f 48 83 e0 f0 49 29 c6 4c 89 f4 48 8b 3d 1c 26 00 00 e8 61 1a 00 00 48 8b 35 a8 25 00 00 48 89 c7 e8 64 1a 00 00 } //01 00 
		$a_00_2 = {48 8b 35 6c 24 00 00 4c 89 ff 4c 89 f2 e8 f5 18 00 00 4c 8b 2d ba 21 00 00 4c 89 f7 41 ff d5 4c 89 ff 41 ff d5 48 8b 35 4f 24 00 00 4c 8b 7d b8 4c 89 ff e8 cf 18 00 00 48 8b 35 2c 24 00 00 4c 8b 75 a8 4c 89 f7 e8 bc 18 00 00 48 89 c7 e8 ba 18 00 00 48 89 c3 48 8b 35 26 24 00 00 48 89 c7 e8 a2 18 00 00 48 89 df 41 ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}