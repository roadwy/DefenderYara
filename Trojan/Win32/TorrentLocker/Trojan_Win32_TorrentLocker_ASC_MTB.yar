
rule Trojan_Win32_TorrentLocker_ASC_MTB{
	meta:
		description = "Trojan:Win32/TorrentLocker.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 db cf 00 00 68 67 fb 07 00 e8 ?? ?? 00 00 83 c4 08 eb } //2
		$a_01_1 = {55 8b ec 81 ec 90 01 00 00 c6 45 d9 39 eb 00 c7 85 } //2
		$a_01_2 = {6d 00 72 00 6f 00 73 00 67 00 6f 00 77 00 7a 00 74 00 79 00 } //1 mrosgowzty
		$a_01_3 = {6b 00 6f 00 65 00 79 00 74 00 75 00 73 00 69 00 34 00 75 00 79 00 74 00 72 00 66 00 73 00 65 00 68 00 64 00 66 00 } //1 koeytusi4uytrfsehdf
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}