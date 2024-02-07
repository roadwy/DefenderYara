
rule Trojan_Win32_BlackMoon_DH_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 14 39 84 d2 7d 0b 66 8b 14 39 66 89 14 01 41 eb 0f 81 e2 ff 00 00 00 8a 92 04 9b 44 00 88 14 01 41 3b ce 72 } //01 00 
		$a_01_1 = {ff 33 8b 5d 80 ff 33 8b 5d 84 ff 33 8b 5d 88 ff 33 8b 5d 8c ff 33 8b 5d 90 ff 33 8b 5d 94 ff 33 8b 5d 98 ff 33 8b 5d 9c ff 33 b9 09 00 00 00 e8 } //01 00 
		$a_01_2 = {68 75 74 61 6f 2e 70 78 78 68 74 2e 69 63 75 2f 64 6f 77 6e 6c 6f 61 64 2e 65 78 65 } //01 00  hutao.pxxht.icu/download.exe
		$a_01_3 = {73 74 66 75 31 2e 70 69 78 78 76 76 2e 63 6c 75 62 } //00 00  stfu1.pixxvv.club
	condition:
		any of ($a_*)
 
}