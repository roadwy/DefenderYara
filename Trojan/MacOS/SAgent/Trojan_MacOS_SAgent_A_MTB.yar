
rule Trojan_MacOS_SAgent_A_MTB{
	meta:
		description = "Trojan:MacOS/SAgent.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 db 49 bc c5 4e ec c4 4e ec c4 4e 4c 8d 35 90 01 02 2c 00 e8 1c 18 00 00 48 63 c8 48 89 c8 49 f7 e4 48 c1 ea 04 48 6b c2 34 48 29 c1 41 8a 04 0e 41 88 04 1f 48 ff c3 49 39 dd 75 d7 90 00 } //01 00 
		$a_03_1 = {49 8b 57 40 49 8b bf 80 00 00 00 49 8b 4f 60 48 01 d1 48 8b 07 4c 89 f6 4c 8d 85 50 ff ff ff ff 50 28 89 c3 4c 8b a5 50 ff ff ff 49 8b 7f 40 49 8b 4f 78 49 29 fc be 01 00 00 00 4c 89 e2 e8 30 0b 00 00 4c 39 e0 0f 85 90 01 04 83 fb 01 90 01 02 83 fb 02 0f 84 90 01 04 49 8b 7f 78 e8 f2 0a 00 00 85 c0 90 00 } //01 00 
		$a_03_2 = {41 83 fd 03 0f 84 90 01 04 41 83 fd 01 0f 87 90 01 04 4c 8b 65 c0 48 8b 7b 40 48 8b 4b 78 49 29 fc be 01 00 00 00 4c 89 e2 e8 0b 06 00 00 4c 39 e0 0f 85 90 01 04 41 83 fd 01 90 01 02 48 8b 55 c8 48 8b 4b 30 48 89 53 28 48 89 4b 38 48 8b bb 80 00 00 00 48 85 ff 90 01 02 4c 8b 4b 40 4c 8b 5b 60 4d 01 cb 4c 8b 17 4c 89 fe 4c 8d 45 c8 48 8d 45 c0 50 41 53 41 ff 52 18 48 83 c4 10 41 89 c5 48 8b 7b 28 48 39 7d c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}