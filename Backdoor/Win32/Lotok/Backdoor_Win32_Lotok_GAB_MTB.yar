
rule Backdoor_Win32_Lotok_GAB_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {66 93 04 db 42 00 00 30 00 00 07 33 80 90 01 04 89 1c db 42 00 00 78 90 01 01 00 54 03 4e b9 90 01 04 30 db 42 00 e7 59 00 00 48 7a 90 00 } //01 00 
		$a_80_1 = {56 69 72 75 73 4b 69 6c 6c 65 72 2e 73 63 72 } //VirusKiller.scr  00 00 
	condition:
		any of ($a_*)
 
}