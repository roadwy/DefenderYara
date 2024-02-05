
rule Trojan_BAT_TrojanDropper_Phonzy_ADG{
	meta:
		description = "Trojan:BAT/TrojanDropper.Phonzy.ADG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 10 00 07 00 00 04 00 "
		
	strings :
		$a_80_0 = {37 63 74 68 4c 76 64 6c 33 49 4c 79 63 50 62 73 58 51 63 6b 42 58 32 46 56 76 48 51 65 67 33 48 62 65 7a 77 46 33 46 4b 6d 77 37 39 75 6e 33 4b 5a 78 6b 6c 71 57 75 } //7cthLvdl3ILycPbsXQckBX2FVvHQeg3HbezwF3FKmw79un3KZxklqWu  04 00 
		$a_80_1 = {78 56 54 51 71 4c 73 77 30 6b 6d 78 48 72 47 6a 49 46 42 71 77 49 6f 78 4b 5a 41 71 59 61 35 70 52 4c 77 56 78 35 6f 70 73 41 46 32 74 37 75 51 6f 59 42 50 61 33 63 4a 4f 69 45 44 64 73 36 73 } //xVTQqLsw0kmxHrGjIFBqwIoxKZAqYa5pRLwVx5opsAF2t7uQoYBPa3cJOiEDds6s  04 00 
		$a_80_2 = {41 54 48 68 36 67 32 73 75 78 49 4b 6a 71 53 61 36 71 62 38 5a 37 46 6f 47 39 57 6c 77 66 39 41 42 72 } //ATHh6g2suxIKjqSa6qb8Z7FoG9Wlwf9ABr  04 00 
		$a_80_3 = {6b 69 33 38 42 65 50 42 7a 70 54 48 64 33 4c 58 54 6a 46 56 7a 64 76 42 4f 51 58 61 4d 48 6c 57 59 6e 34 77 6d 46 55 53 6e 4d 4b 78 6a 39 53 47 6b 4c 44 49 59 77 37 66 65 61 61 69 68 74 75 53 47 72 52 67 4b 6d 63 34 35 6e } //ki38BePBzpTHd3LXTjFVzdvBOQXaMHlWYn4wmFUSnMKxj9SGkLDIYw7feaaihtuSGrRgKmc45n  03 00 
		$a_80_4 = {44 65 63 72 79 70 74 65 72 44 61 74 61 } //DecrypterData  03 00 
		$a_80_5 = {54 61 73 6b 53 63 68 65 64 75 6c 65 72 } //TaskScheduler  02 00 
		$a_80_6 = {57 69 6e 64 6f 77 73 5c 4d 65 64 69 61 5c 4c 6f 67 } //Windows\Media\Log  00 00 
	condition:
		any of ($a_*)
 
}