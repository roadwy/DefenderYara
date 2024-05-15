
rule Trojan_Win32_KillFiles_RP_MTB{
	meta:
		description = "Trojan:Win32/KillFiles.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe ca c0 c9 60 f6 da 66 c1 c1 c1 d0 ca 66 d3 c9 f9 80 f2 02 32 da 66 0b cf 32 c8 66 8b 0c 14 66 0f ba e2 c1 } //0a 00 
		$a_03_1 = {55 52 0f b7 ed 8b 74 24 14 c7 44 24 14 90 01 04 81 44 24 04 90 01 04 66 f7 dd 66 2b 6c 24 05 e8 90 01 04 f7 d0 e9 90 01 04 fe c0 f8 32 d8 66 89 14 04 c0 c4 34 66 0f ba f0 74 e9 90 00 } //01 00 
		$a_03_2 = {f9 81 ed 02 00 00 00 f9 66 89 4c 25 00 66 81 c9 58 28 8b 0e 81 c6 04 00 00 00 f5 33 cb d1 c9 f6 c1 82 3b f2 85 c4 81 c1 90 01 04 d1 c9 f8 f5 81 f1 90 01 04 e9 90 00 } //0a 00 
		$a_03_3 = {8b 0e 66 41 d3 db 66 45 8b 5e 08 40 f6 d7 44 0f ab ef 49 81 c6 0a 00 00 00 36 66 45 89 19 40 80 ef 2d f5 48 81 ee 04 00 00 00 48 0f b7 ff 8b 3e f7 c1 90 01 04 45 3a f8 41 33 f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}