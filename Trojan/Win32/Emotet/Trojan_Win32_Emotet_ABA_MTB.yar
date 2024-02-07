
rule Trojan_Win32_Emotet_ABA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ABA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {99 bd 4d 2c 00 00 8b cd f7 f9 8b 44 24 3c 2b 54 24 30 03 54 24 34 03 54 24 38 8b ca 0f b6 04 08 03 c6 99 f7 fd 8b 44 24 4c 8a 04 08 } //02 00 
		$a_01_1 = {8b 54 24 58 0f b6 14 32 89 44 24 28 8b 44 24 54 0f 42 36 04 08 03 c2 99 bd 4d 2c 00 00 f7 fd 8b 44 24 60 8b 6c 24 28 2b d7 2b 54 24 1c 03 d3 8a 04 02 30 45 00 ff 44 24 10 } //04 00 
		$a_01_2 = {35 6d 61 53 37 5a 30 5a 78 21 7a 36 6d 4a 79 35 66 66 23 29 40 24 2a 33 3f 30 71 45 71 33 28 76 41 42 49 52 71 65 48 42 21 33 43 50 6c 34 58 6a 43 54 74 58 51 5f 32 47 6b 61 42 3e 71 53 62 2a 48 4f 44 28 40 34 65 4c 51 5a 66 5f 42 4e 52 6c 70 66 77 67 } //00 00  5maS7Z0Zx!z6mJy5ff#)@$*3?0qEq3(vABIRqeHB!3CPl4XjCTtXQ_2GkaB>qSb*HOD(@4eLQZf_BNRlpfwg
	condition:
		any of ($a_*)
 
}