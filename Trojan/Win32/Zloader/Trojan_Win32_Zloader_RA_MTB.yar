
rule Trojan_Win32_Zloader_RA_MTB{
	meta:
		description = "Trojan:Win32/Zloader.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 63 6c 65 61 6e 5c 74 68 65 72 65 5c 63 6c 6f 74 68 65 5c 77 69 6e 74 65 72 5c 46 72 61 63 74 69 6f 6e 5c 72 61 63 65 5c 43 61 72 64 5c 57 6f 72 6c 64 63 6c 6f 75 64 2e 70 64 62 } //01 00  c:\clean\there\clothe\winter\Fraction\race\Card\Worldcloud.pdb
		$a_01_1 = {6d 61 69 6e 2e 64 6c 6c } //01 00  main.dll
		$a_01_2 = {44 72 79 73 74 72 61 6e 67 65 31 } //01 00  Drystrange1
		$a_01_3 = {4c 69 67 68 74 73 68 65 65 74 40 31 32 } //01 00  Lightsheet@12
		$a_80_4 = {63 3a 5c 74 61 6c 6b 5c 54 75 72 6e 5c 73 65 70 61 72 61 74 65 5c 54 69 6d 65 5c 53 70 6f 74 5c 53 74 61 74 69 6f 6e 5c 54 6f 67 65 74 68 65 72 6e 6f 74 69 63 65 2e 70 64 62 } //c:\talk\Turn\separate\Time\Spot\Station\Togethernotice.pdb  01 00 
		$a_01_5 = {8b d0 6b d2 43 8b f9 6b ff 43 2b f2 8b d6 2b d7 8d 7c 02 5c 66 01 3d } //03 00 
		$a_03_6 = {81 c2 84 23 01 01 89 15 90 01 04 a1 90 01 04 03 45 90 02 05 8b 0d 90 1b 00 89 88 38 ed ff ff 90 00 } //00 00 
		$a_00_7 = {5d 04 00 } //00 1b 
	condition:
		any of ($a_*)
 
}