
rule Trojan_Win32_Guildma_psyA_MTB{
	meta:
		description = "Trojan:Win32/Guildma.psyA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {f7 f3 44 8e 63 f3 c6 b0 da dd 61 19 1b ba a4 67 71 77 7c 3a 31 1c 08 93 5b ea 81 ef 64 85 38 c0 65 30 8e 98 f6 6f 4b c4 7e b1 8c 8d 5f 18 ee 91 3f 98 a5 84 25 a1 47 82 67 35 a8 54 39 61 94 15 e6 72 b6 62 7d e0 c4 83 ae e6 0b 0e 3c e8 77 d9 a7 c3 dd 95 0c 08 74 2b 66 62 fd 72 74 1b df 48 c8 73 f5 } //00 00 
	condition:
		any of ($a_*)
 
}