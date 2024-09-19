
rule TrojanDownloader_BAT_Rozena_DHE_MTB{
	meta:
		description = "TrojanDownloader:BAT/Rozena.DHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {42 79 70 61 73 73 4c 6f 61 64 2e 65 78 65 } //5 BypassLoad.exe
		$a_00_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6a 00 63 00 78 00 6a 00 67 00 2e 00 66 00 75 00 6e 00 2f 00 74 00 65 00 73 00 74 00 2f 00 64 00 65 00 5f 00 73 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00 } //1 https://jcxjg.fun/test/de_shellcode
		$a_00_2 = {42 79 70 61 73 73 4c 6f 61 64 2e 70 64 62 } //1 BypassLoad.pdb
		$a_00_3 = {42 00 73 00 69 00 6a 00 56 00 55 00 76 00 32 00 76 00 2b 00 51 00 6c 00 2f 00 4e 00 4d 00 33 00 70 00 51 00 76 00 38 00 75 00 51 00 3d 00 3d 00 } //1 BsijVUv2v+Ql/NM3pQv8uQ==
		$a_00_4 = {41 00 79 00 44 00 39 00 59 00 39 00 7a 00 57 00 39 00 64 00 74 00 76 00 66 00 71 00 4a 00 7a 00 4a 00 62 00 33 00 33 00 67 00 41 00 3d 00 3d 00 } //1 AyD9Y9zW9dtvfqJzJb33gA==
	condition:
		((#a_81_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}