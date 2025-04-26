
rule Trojan_Win32_IcedId_DEH_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_02_0 = {83 c4 48 53 6a 01 53 53 8d 4c 24 ?? 51 ff 15 ?? ?? ?? ?? 85 c0 75 3a 6a 08 6a 01 53 53 8d 54 24 90 1b 00 52 ff 15 90 1b 01 85 c0 } //1
		$a_81_1 = {46 47 44 41 46 47 53 44 53 46 47 53 44 53 46 47 53 44 46 47 47 48 46 44 64 74 79 64 72 54 46 53 46 47 53 44 41 67 66 73 64 67 66 73 } //1 FGDAFGSDSFGSDSFGSDFGGHFDdtydrTFSFGSDAgfsdgfs
		$a_81_2 = {30 36 57 59 70 34 4b 75 56 34 36 31 31 58 77 6a 71 48 64 69 75 42 31 6a 62 30 4a 4e 68 55 5a 4c 68 7a 55 51 36 56 34 4d 32 53 36 49 31 67 46 58 70 79 78 45 32 4d 51 42 66 4a 75 34 69 69 67 79 } //1 06WYp4KuV4611XwjqHdiuB1jb0JNhUZLhzUQ6V4M2S6I1gFXpyxE2MQBfJu4iigy
		$a_81_3 = {71 78 6e 56 58 35 59 52 6f 6e 69 61 35 4c 49 6b 6e 6b 4c 51 55 63 66 4c 4f 38 4e 59 76 6b 63 78 31 6d 6f 34 6e 73 31 56 48 30 79 } //1 qxnVX5YRonia5LIknkLQUcfLO8NYvkcx1mo4ns1VH0y
		$a_81_4 = {6b 39 48 6c 58 73 35 6a 35 4d 46 34 6e 6d 4e } //1 k9HlXs5j5MF4nmN
		$a_81_5 = {65 4f 72 53 48 73 62 6b 74 35 57 47 4d 39 73 } //1 eOrSHsbkt5WGM9s
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=1
 
}