
rule TrojanDownloader_Win32_Agent_AAJ{
	meta:
		description = "TrojanDownloader:Win32/Agent.AAJ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 6d 73 6e 6e 65 74 77 6f 72 6b 2e 6e 65 74 } //2 www.msnnetwork.net
		$a_01_1 = {5a 56 77 6b 56 62 78 74 33 58 64 4e 62 45 6b 73 56 5a 68 69 54 6d 4d 70 63 30 74 69 4e 4d 59 44 } //3 ZVwkVbxt3XdNbEksVZhiTmMpc0tiNMYD
		$a_01_2 = {6e 6f 77 20 75 70 67 72 61 64 69 6e 67 2e 2e 2e 2e 2e 21 } //2 now upgrading.....!
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=7
 
}