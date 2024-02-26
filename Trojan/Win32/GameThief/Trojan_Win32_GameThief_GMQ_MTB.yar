
rule Trojan_Win32_GameThief_GMQ_MTB{
	meta:
		description = "Trojan:Win32/GameThief.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {45 64 69 74 41 90 01 01 73 77 65 72 32 48 03 00 00 01 00 08 45 64 69 74 50 90 01 01 65 72 4c 03 90 00 } //01 00 
		$a_01_1 = {4f 4c 47 61 6d 65 2e 69 74 6d } //00 00  OLGame.itm
	condition:
		any of ($a_*)
 
}