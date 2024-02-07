
rule Trojan_Win32_Relbma_A_dll{
	meta:
		description = "Trojan:Win32/Relbma.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 09 00 "
		
	strings :
		$a_03_0 = {2b d6 80 b4 05 f0 fd ff ff 90 01 01 80 b4 05 f1 fd ff ff 90 01 01 80 b4 05 f2 fd ff ff 90 01 01 83 c0 03 8d 34 02 8d b4 35 f1 fd ff ff 3b f1 72 d7 3b c1 73 08 80 b4 05 f0 fd ff ff 90 01 01 8d 50 01 90 00 } //02 00 
		$a_00_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 52 75 6e 4d 61 69 6e 00 } //02 00  畲摮汬㈳攮數┠ⱳ畒䵮楡n
		$a_00_2 = {6d 62 75 72 6c 00 00 00 62 75 72 6c 00 00 00 00 6d 62 74 65 78 74 00 00 62 74 65 78 74 00 } //01 00 
		$a_00_3 = {79 61 6e 64 65 78 } //01 00  yandex
		$a_00_4 = {63 6c 69 63 6b 72 65 66 65 72 65 72 } //01 00  clickreferer
		$a_00_5 = {66 65 65 64 } //01 00  feed
		$a_00_6 = {00 5f 57 53 43 4c 41 53 5f 00 } //01 00  开南䱃十_
		$a_00_7 = {70 6f 70 75 72 6c } //02 00  popurl
		$a_00_8 = {63 6c 61 73 73 3d 79 73 63 68 74 74 6c 00 } //00 00  汣獡㵳獹档瑴l
	condition:
		any of ($a_*)
 
}