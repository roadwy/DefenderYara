
rule Trojan_Win32_Gawime_A{
	meta:
		description = "Trojan:Win32/Gawime.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 0a 00 00 03 00 "
		
	strings :
		$a_01_0 = {83 c4 18 84 c0 5e 74 19 ff 75 14 ff 75 10 ff 75 0c ff 75 08 e8 } //01 00 
		$a_01_1 = {43 3a 5c 74 6d 70 2e 64 6f 77 6e 00 } //01 00  㩃瑜灭搮睯n
		$a_01_2 = {44 6c 6c 52 75 6e 69 6e 67 00 00 00 3a 00 } //01 00 
		$a_01_3 = {2e 6c 6e 6b 00 00 00 00 5c 00 00 00 25 64 2d 25 64 2d 25 64 20 25 64 3a 25 64 3a 25 64 00 } //01 00 
		$a_01_4 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 00 00 00 3a 6b 69 6c 6c } //01 00 
		$a_01_5 = {69 66 20 25 65 72 72 6f 72 6c 65 76 65 6c 25 3d 3d 31 20 28 67 6f 74 6f 20 6b 69 6c 6c 29 } //01 00  if %errorlevel%==1 (goto kill)
		$a_01_6 = {74 61 73 6b 6c 69 73 74 20 7c 66 69 6e 64 } //01 00  tasklist |find
		$a_01_7 = {57 69 6e 47 61 6d 65 5f } //01 00  WinGame_
		$a_01_8 = {5c 38 37 6f 6d 33 73 32 75 2e 65 78 65 00 } //01 00 
		$a_01_9 = {5c 70 6f 62 61 6f 5f 64 68 78 79 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}