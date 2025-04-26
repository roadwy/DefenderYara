
rule Trojan_Win32_GameThief_GMQ_MTB{
	meta:
		description = "Trojan:Win32/GameThief.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 64 69 74 41 ?? 73 77 65 72 32 48 03 00 00 01 00 08 45 64 69 74 50 ?? 65 72 4c 03 } //10
		$a_01_1 = {4f 4c 47 61 6d 65 2e 69 74 6d } //1 OLGame.itm
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}