
rule TrojanDownloader_BAT_Trolex_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/Trolex.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 07 93 0c 08 1f 61 32 ?? 08 1f 7a 30 ?? 08 1f 6d 31 ?? 08 1f 0d 59 0c 2b ?? 08 1f 0d 58 0c 2b ?? 08 1f 41 32 ?? 08 1f 5a 30 ?? 08 1f 4d 31 ?? 08 1f 0d 59 0c 2b ?? 08 1f 0d 58 0c 06 07 08 d1 9d 07 17 58 0b } //1
		$a_01_1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 20 00 2d 00 64 00 65 00 63 00 6f 00 64 00 65 00 } //1 cmd /c certutil -decode
		$a_01_2 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 73 00 63 00 20 00 4d 00 49 00 4e 00 55 00 54 00 45 00 20 00 2f 00 6d 00 6f 00 20 00 33 00 20 00 2f 00 74 00 6e 00 } //1 /create /sc MINUTE /mo 3 /tn
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}