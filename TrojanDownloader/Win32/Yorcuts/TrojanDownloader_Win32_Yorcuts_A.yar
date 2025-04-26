
rule TrojanDownloader_Win32_Yorcuts_A{
	meta:
		description = "TrojanDownloader:Win32/Yorcuts.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 65 6c 6c 6d 65 57 68 79 6f 6b 2e 61 63 6c } //1 TellmeWhyok.acl
		$a_01_1 = {53 69 67 56 65 72 } //1 SigVer
		$a_01_2 = {31 32 30 30 } //1 1200
		$a_01_3 = {70 77 65 66 6e 78 61 6c 6b 73 31 32 38 39 33 6b 61 6e 63 30 39 32 33 6a 61 61 64 63 61 61 65 33 } //1 pwefnxalks12893kanc0923jaadcaae3
		$a_01_4 = {8a 06 2a 01 79 02 04 5e 04 20 88 02 8a 41 01 42 41 84 c0 75 02 8b cb 8a 46 01 46 84 c0 75 e1 83 c9 ff 33 c0 f2 ae f7 d1 49 5f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}