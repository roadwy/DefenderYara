
rule Trojan_Win32_Ekstak_GMI_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c4 14 48 89 35 9c fa 46 00 5f 5e a3 98 fa 46 00 5b c9 c3 } //0a 00 
		$a_03_1 = {56 53 ff 15 90 01 04 a1 90 01 01 01 47 00 89 35 90 01 01 fa 46 00 8b fe 38 18 90 00 } //01 00 
		$a_80_2 = {53 34 42 41 4d 50 6c 61 79 65 72 2e 65 78 65 } //S4BAMPlayer.exe  00 00 
	condition:
		any of ($a_*)
 
}