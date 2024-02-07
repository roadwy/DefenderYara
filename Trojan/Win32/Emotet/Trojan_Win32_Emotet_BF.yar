
rule Trojan_Win32_Emotet_BF{
	meta:
		description = "Trojan:Win32/Emotet.BF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {08 c4 58 c6 86 9f 4c 68 c6 f4 4c 68 08 c5 28 c6 8f 0c 68 c6 4c 68 c6 08 c5 78 c6 8f 4c 68 c5 } //01 00 
		$a_02_1 = {00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 90 02 02 00 65 00 63 00 75 00 72 00 69 00 74 00 00 90 00 } //01 00 
		$a_00_2 = {00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 53 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 00 } //01 00 
		$a_01_3 = {68 57 45 48 57 23 40 48 4a 45 52 4b 4a 45 52 4a 45 52 5e 24 2e 50 64 62 } //00 00  hWEHW#@HJERKJERJER^$.Pdb
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_BF_2{
	meta:
		description = "Trojan:Win32/Emotet.BF,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 72 66 5a 50 70 32 43 2e 70 64 62 } //01 00  XrfZPp2C.pdb
		$a_01_1 = {4c 51 59 75 74 6f 58 52 4a 70 51 42 49 2d 7a 79 56 65 2e 70 64 62 } //00 00  LQYutoXRJpQBI-zyVe.pdb
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_BF_3{
	meta:
		description = "Trojan:Win32/Emotet.BF,SIGNATURE_TYPE_PEHSTR,01 00 01 00 12 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 5f 44 21 41 79 3d 56 61 44 79 61 4b 44 61 2e 70 64 62 } //01 00  t_D!Ay=VaDyaKDa.pdb
		$a_01_1 = {65 72 6a 52 57 4a 45 52 4a 6b 65 74 6b 6a 51 45 57 59 48 4a 40 23 2e 50 64 62 } //01 00  erjRWJERJketkjQEWYHJ@#.Pdb
		$a_01_2 = {79 6e 6d 4e 61 31 4f 6a 4b 64 55 69 65 2e 70 64 62 } //01 00  ynmNa1OjKdUie.pdb
		$a_01_3 = {4a 4f 65 7c 4f 42 7a 6a 41 54 63 6b 23 70 73 62 2f 2e 70 64 62 } //01 00  JOe|OBzjATck#psb/.pdb
		$a_01_4 = {68 6b 68 6a 67 67 68 2e 50 64 62 } //01 00  hkhjggh.Pdb
		$a_01_5 = {43 72 79 41 52 72 2e 70 64 62 } //01 00  CryARr.pdb
		$a_01_6 = {7a 59 41 61 6d 54 47 42 32 72 66 57 21 43 70 2b 61 52 2e 70 64 62 } //01 00  zYAamTGB2rfW!Cp+aR.pdb
		$a_01_7 = {65 77 68 77 77 68 65 72 47 57 2e 50 64 62 } //01 00  ewhwwherGW.Pdb
		$a_01_8 = {68 65 77 72 6a 6b 72 6b 74 65 72 23 77 68 72 6a 65 40 77 67 2e 50 64 62 } //01 00  hewrjkrkter#whrje@wg.Pdb
		$a_01_9 = {75 69 67 6a 68 67 68 69 6f 2e 70 64 62 } //01 00  uigjhghio.pdb
		$a_01_10 = {51 50 4b 2b 4c 62 5a 6a 62 2a 34 4b 56 40 49 6e 59 51 2a 2e 70 64 62 } //01 00  QPK+LbZjb*4KV@InYQ*.pdb
		$a_01_11 = {6f 64 75 62 71 61 2e 70 64 62 } //01 00  odubqa.pdb
		$a_01_12 = {37 68 34 71 4d 51 31 65 64 76 45 4f 59 2b 77 51 49 4f 64 56 52 5f 76 2e 70 64 62 } //01 00  7h4qMQ1edvEOY+wQIOdVR_v.pdb
		$a_01_13 = {33 56 76 40 70 3d 69 38 71 67 2e 79 6c 51 4a 78 78 21 6c 2e 70 64 62 } //01 00  3Vv@p=i8qg.ylQJxx!l.pdb
		$a_01_14 = {48 58 65 35 2b 47 45 4e 78 53 68 4d 2e 70 64 62 } //01 00  HXe5+GENxShM.pdb
		$a_01_15 = {32 65 7a 55 56 47 72 21 50 74 42 2e 70 64 62 } //01 00  2ezUVGr!PtB.pdb
		$a_01_16 = {69 77 4a 4c 23 23 24 40 23 2a 24 5e 23 25 40 21 5e 24 2e 70 64 62 } //01 00  iwJL##$@#*$^#%@!^$.pdb
		$a_01_17 = {65 54 69 71 5f 57 61 45 4e 5f 5f 79 39 46 38 39 7a 4c 75 6b 6a 6d 4d 2e 70 64 62 } //00 00  eTiq_WaEN__y9F89zLukjmM.pdb
	condition:
		any of ($a_*)
 
}