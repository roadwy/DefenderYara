
rule TrojanDownloader_Win64_Johnnygo_A_dha{
	meta:
		description = "TrojanDownloader:Win64/Johnnygo.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //1 expand 32-byte kexpand 32-byte k
		$a_01_1 = {63 3a 2f 67 6f 2f 77 6f 72 6b 2f 73 65 72 76 69 63 65 49 49 2f 73 65 72 76 69 63 65 2e 67 6f } //1 c:/go/work/serviceII/service.go
		$a_01_2 = {63 3a 2f 67 6f 2f 73 72 63 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 6b 61 72 64 69 61 6e 6f 73 2f 73 65 72 76 69 63 65 2f 73 65 72 76 69 63 65 2e 67 6f } //1 c:/go/src/github.com/kardianos/service/service.go
		$a_01_3 = {43 3a 2f 55 73 65 72 73 2f 6a 6f 68 6e 2f 67 6f 2f 73 72 63 2f 67 6f 6c 61 6e 67 2e 6f 72 67 2f 78 2f 73 79 73 2f 77 69 6e 64 6f 77 73 2f 73 76 63 2f 73 65 72 76 69 63 65 2e 67 6f } //1 C:/Users/john/go/src/golang.org/x/sys/windows/svc/service.go
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}