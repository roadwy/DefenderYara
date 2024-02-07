
rule Trojan_Win32_Killav_GL{
	meta:
		description = "Trojan:Win32/Killav.GL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {33 36 30 74 72 61 79 3b 61 76 67 6e 74 3b 61 76 67 61 75 72 64 3b 61 76 63 65 6e 74 65 72 3b 61 64 61 6d 3b 41 67 65 6e 74 53 76 72 3b 41 6e 74 69 41 72 70 3b } //01 00  360tray;avgnt;avgaurd;avcenter;adam;AgentSvr;AntiArp;
		$a_00_1 = {3b 6b 69 73 73 76 63 3b 6b 73 77 65 62 73 68 69 65 6c 64 3b 5a 68 75 44 6f 6e 67 46 61 6e 67 59 75 3b 53 75 70 65 72 4b 69 6c 6c 65 72 3b } //01 00  ;kissvc;kswebshield;ZhuDongFangYu;SuperKiller;
		$a_03_2 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 7e 90 02 10 2e 74 78 74 90 02 15 4f 48 48 62 68 50 72 6f 90 00 } //01 00 
		$a_03_3 = {ba 78 4d 00 00 e8 90 01 04 6a 00 8d 45 90 01 01 50 68 78 4d 00 00 90 00 } //01 00 
		$a_03_4 = {7c 14 46 33 d2 33 db 8a 1c 10 66 81 f3 90 01 02 88 1c 11 42 4e 75 ef 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}