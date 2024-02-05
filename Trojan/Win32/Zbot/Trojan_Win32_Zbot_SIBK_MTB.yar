
rule Trojan_Win32_Zbot_SIBK_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 0c 00 00 01 00 "
		
	strings :
		$a_02_0 = {69 72 63 2e 90 02 05 2e 62 79 90 00 } //01 00 
		$a_80_1 = {43 3a 5c 6c 6f 67 2e 74 78 74 } //C:\log.txt  01 00 
		$a_80_2 = {6b 69 62 65 72 5f 73 6f 6c 64 69 65 72 73 } //kiber_soldiers  01 00 
		$a_80_3 = {21 73 68 75 74 75 70 } //!shutup  01 00 
		$a_80_4 = {21 73 68 75 74 64 6f 77 6e } //!shutdown  01 00 
		$a_80_5 = {21 50 32 50 49 4e 46 45 43 54 } //!P2PINFECT  01 00 
		$a_80_6 = {21 4c 4f 41 44 } //!LOAD  01 00 
		$a_80_7 = {5c 73 6f 66 74 77 61 72 65 5c 4d 6f 72 70 68 65 75 73 } //\software\Morpheus  01 00 
		$a_80_8 = {5c 73 6f 66 74 77 61 72 65 5c 58 6f 6c 6f 78 } //\software\Xolox  01 00 
		$a_80_9 = {5c 73 6f 66 74 77 61 72 65 5c 4b 61 7a 61 61 } //\software\Kazaa  01 00 
		$a_80_10 = {5c 73 6f 66 74 77 61 72 65 5c 53 68 61 72 65 61 7a 61 } //\software\Shareaza  01 00 
		$a_80_11 = {5c 73 6f 66 74 77 61 72 65 5c 4c 69 6d 65 57 69 72 65 } //\software\LimeWire  00 00 
	condition:
		any of ($a_*)
 
}