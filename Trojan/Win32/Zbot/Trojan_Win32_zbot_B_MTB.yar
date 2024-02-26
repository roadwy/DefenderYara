
rule Trojan_Win32_Zbot_B_MTB{
	meta:
		description = "Trojan:Win32/Zbot.B!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 10 00 00 00 8a 0c 37 30 0e 46 48 75 f7 } //01 00 
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 64 65 67 72 69 67 69 73 5c 64 6f 63 75 6d 65 6e 74 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 32 30 31 30 5c 50 72 6f 6a 65 63 74 73 5c 44 6f 6c 70 68 69 6e 44 72 6f 70 70 65 72 41 45 53 5c 52 65 6c 65 61 73 65 5c 44 6f 6c 70 68 69 6e 44 72 6f 70 70 65 72 41 45 53 2e 70 64 62 } //01 00  C:\Users\degrigis\documents\visual studio 2010\Projects\DolphinDropperAES\Release\DolphinDropperAES.pdb
		$a_01_2 = {88 48 11 0f b6 50 f2 32 55 ff 8d 4e fe 88 50 12 83 c0 10 } //00 00 
	condition:
		any of ($a_*)
 
}