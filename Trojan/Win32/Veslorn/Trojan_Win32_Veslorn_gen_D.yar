
rule Trojan_Win32_Veslorn_gen_D{
	meta:
		description = "Trojan:Win32/Veslorn.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 42 46 44 44 4f 53 2f 25 64 2d 25 64 00 } //01 00  䈀䑆佄⽓搥┭d
		$a_01_1 = {00 46 59 48 48 4f 53 3d 25 64 2b 25 64 28 4d 42 29 00 } //01 00  䘀䡙佈㵓搥┫⡤䉍)
		$a_01_2 = {00 46 59 59 4c 43 53 3d 25 64 2b 25 64 28 4d 42 29 } //05 00 
		$a_01_3 = {00 41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e 0d 0a } //05 00 
		$a_01_4 = {41 54 54 41 43 4b } //05 00  ATTACK
		$a_01_5 = {00 52 45 54 55 52 4e 50 4f 57 45 52 } //00 00  刀呅剕偎坏剅
	condition:
		any of ($a_*)
 
}