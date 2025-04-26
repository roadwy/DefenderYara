
rule Trojan_Win64_TrojanDownloader_NIT_MTB{
	meta:
		description = "Trojan:Win64/TrojanDownloader.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 72 65 6d 6f 74 65 5f 63 73 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 72 65 6d 6f 74 65 5f 63 73 2e 70 64 62 } //2 \remote_cs\x64\Release\remote_cs.pdb
		$a_01_1 = {4d 58 58 46 45 47 59 43 41 59 46 43 4e 59 46 46 45 4d 4f 4f 4f 4f 58 } //2 MXXFEGYCAYFCNYFFEMOOOOX
		$a_01_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 57 } //1 InternetOpenW
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}