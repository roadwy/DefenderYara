
rule Trojan_Win64_DCRat_PD_MTB{
	meta:
		description = "Trojan:Win64/DCRat.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 } //1 Go build ID: 
		$a_01_1 = {70 6f 72 74 67 65 74 61 64 64 72 69 6e 66 6f 77 74 72 61 6e 73 6d 69 74 66 69 6c 65 } //1 portgetaddrinfowtransmitfile
		$a_01_2 = {6e 65 74 2f 68 74 74 70 2e 66 61 6b 65 4c 6f 63 6b 65 72 2c 73 79 6e 63 2e 4c 6f 63 6b 65 72 } //1 net/http.fakeLocker,sync.Locker
		$a_01_3 = {67 69 74 68 75 62 2e 63 6f 6d 2f 4d 72 42 72 6f 75 6e 72 2f 6d 61 69 6e 2f 72 61 77 2f 6d 61 69 6e 2f 6e 61 6b 65 72 2e 65 78 65 } //3 github.com/MrBrounr/main/raw/main/naker.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3) >=6
 
}