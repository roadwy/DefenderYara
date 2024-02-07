
rule Trojan_BAT_KamiKakaBot_MA_MTB{
	meta:
		description = "Trojan:BAT/KamiKakaBot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 06 02 06 91 20 90 01 04 61 d2 9c 38 90 01 04 02 06 02 06 91 20 90 01 04 61 d2 9c 06 17 58 0a 06 02 8e 69 32 cf 90 00 } //01 00 
		$a_01_1 = {37 38 63 61 61 37 65 62 2d 36 34 62 37 2d 34 36 66 39 2d 38 66 37 64 2d 30 39 32 32 62 37 38 39 31 39 35 33 } //01 00  78caa7eb-64b7-46f9-8f7d-0922b7891953
		$a_01_2 = {2f 00 73 00 65 00 6e 00 64 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 3f 00 63 00 68 00 61 00 74 00 5f 00 69 00 64 00 3d 00 } //01 00  /sendDocument?chat_id=
		$a_01_3 = {3f 00 63 00 61 00 70 00 74 00 69 00 6f 00 6e 00 3d 00 } //01 00  ?caption=
		$a_01_4 = {4b 00 61 00 6d 00 69 00 2e 00 64 00 6c 00 6c 00 } //00 00  Kami.dll
	condition:
		any of ($a_*)
 
}