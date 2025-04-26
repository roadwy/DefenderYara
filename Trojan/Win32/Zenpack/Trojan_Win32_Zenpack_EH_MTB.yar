
rule Trojan_Win32_Zenpack_EH_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {fd ff ff 0f b6 c8 83 e9 33 8b 95 ?? fd ff ff 89 8d ?? fd ff ff 89 95 d8 fd ff ff 74 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}
rule Trojan_Win32_Zenpack_EH_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpack.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 56 8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 c7 05 ?? ?? ?? ?? 97 00 00 00 8a 24 0a 28 c4 c7 05 ?? ?? ?? ?? 5d 08 00 00 88 24 0e 5e 5d c3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Zenpack_EH_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpack.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 00 6f 00 76 00 69 00 6e 00 67 00 74 00 77 00 6f 00 44 00 69 00 73 00 6e 00 2e 00 74 00 75 00 73 00 45 00 6d 00 61 00 6e 00 6c 00 61 00 6e 00 64 00 } //1 MovingtwoDisn.tusEmanland
		$a_01_1 = {6f 00 62 00 6c 00 65 00 73 00 73 00 65 00 64 00 66 00 6f 00 72 00 74 00 68 00 75 00 6e 00 64 00 65 00 72 00 49 00 74 00 68 00 65 00 79 00 2e 00 72 00 65 00 2e 00 42 00 6d 00 61 00 64 00 65 00 74 00 68 00 65 00 79 00 2e 00 72 00 65 00 } //1 oblessedforthunderIthey.re.Bmadethey.re
		$a_01_2 = {77 00 61 00 74 00 65 00 72 00 73 00 47 00 71 00 53 00 6b 00 46 00 73 00 6f 00 6d 00 46 00 6f 00 76 00 65 00 72 00 } //1 watersGqSkFsomFover
		$a_01_3 = {37 00 4f 00 6e 00 65 00 62 00 65 00 61 00 73 00 74 00 46 00 } //1 7OnebeastF
		$a_01_4 = {75 00 6e 00 64 00 65 00 72 00 6e 00 53 00 65 00 65 00 64 00 53 00 65 00 61 00 73 00 } //1 undernSeedSeas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}