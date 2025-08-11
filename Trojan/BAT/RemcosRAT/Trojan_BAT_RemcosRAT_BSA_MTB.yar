
rule Trojan_BAT_RemcosRAT_BSA_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 03 00 00 "
		
	strings :
		$a_01_0 = {5a 57 4d 32 4d 7a 4a 6d 5a 44 6b 74 4d 54 59 35 4e 43 30 30 5a 6a 52 68 4c 54 6c 69 5a 6d 59 74 5a 6a 49 77 4e 6a 41 77 5a 54 4d 33 4f 54 67 78 } //1 ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx
		$a_01_1 = {63 38 62 38 64 62 63 30 61 32 34 61 63 65 34 62 61 61 63 35 35 31 63 37 33 64 39 62 64 63 64 35 35 } //10 c8b8dbc0a24ace4baac551c73d9bdcd55
		$a_01_2 = {45 78 65 63 75 74 65 00 70 61 74 68 00 70 61 79 6c 6f 61 64 } //14 硅捥瑵e慰桴瀀祡潬摡
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*14) >=25
 
}