
rule TrojanSpy_Win32_Banker_XO{
	meta:
		description = "TrojanSpy:Win32/Banker.XO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56 ed } //02 00 
		$a_03_1 = {8b 55 08 8b 7d 10 0f be 04 13 2b c7 43 88 44 0d 90 01 01 41 83 f9 04 7c e9 90 00 } //01 00 
		$a_03_2 = {64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8d 90 01 04 00 66 c7 40 24 60 00 89 90 01 01 28 90 00 } //01 00 
		$a_00_3 = {3c 2f 42 3e 3c 53 50 41 4e 20 69 64 3d 62 61 6e 6b 2d 6e 61 6d 65 3e } //01 00  </B><SPAN id=bank-name>
		$a_00_4 = {42 41 4e 4b 3d 25 73 26 51 49 41 4e 3d 25 73 26 41 4c 49 50 41 59 4e 41 4d 45 3d 25 73 26 41 4c 49 50 41 59 56 45 52 3d 25 73 } //01 00  BANK=%s&QIAN=%s&ALIPAYNAME=%s&ALIPAYVER=%s
		$a_00_5 = {25 73 2f 50 61 79 54 6f 4d 65 2f 54 42 5f 50 61 79 2e 41 73 70 3f 6e 46 6c 61 67 3d 30 26 55 73 65 72 4e 61 6d 65 3d 25 73 } //00 00  %s/PayToMe/TB_Pay.Asp?nFlag=0&UserName=%s
	condition:
		any of ($a_*)
 
}