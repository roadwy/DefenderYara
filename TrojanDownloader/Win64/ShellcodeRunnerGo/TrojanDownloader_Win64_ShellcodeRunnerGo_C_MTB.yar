
rule TrojanDownloader_Win64_ShellcodeRunnerGo_C_MTB{
	meta:
		description = "TrojanDownloader:Win64/ShellcodeRunnerGo.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {73 79 73 63 61 6c 6c 2e 52 61 77 53 6f 63 6b 61 64 64 72 41 6e 79 } //1 syscall.RawSockaddrAny
		$a_81_1 = {70 65 2e 52 65 6c 6f 63 45 6e 74 72 79 } //1 pe.RelocEntry
		$a_81_2 = {65 6e 63 6f 64 69 6e 67 2f 67 6f 62 2f 65 6e 63 6f 64 65 72 2e 67 6f } //1 encoding/gob/encoder.go
		$a_81_3 = {67 69 74 68 75 62 2e 63 6f 6d 2f 73 65 74 68 67 72 69 64 2f 70 65 73 74 65 72 } //1 github.com/sethgrid/pester
		$a_81_4 = {74 65 78 74 2f 74 65 6d 70 6c 61 74 65 2f 65 78 65 63 2e 67 6f } //1 text/template/exec.go
		$a_81_5 = {76 65 6e 64 6f 72 2f 67 6f 6c 61 6e 67 2e 6f 72 67 2f 78 2f 6e 65 74 2f 68 74 74 70 2f 68 74 74 70 70 72 6f 78 79 2f 70 72 6f 78 79 2e 67 6f } //1 vendor/golang.org/x/net/http/httpproxy/proxy.go
		$a_81_6 = {6e 65 74 2f 68 74 74 70 2f 63 6f 6f 6b 69 65 2e 67 6f } //1 net/http/cookie.go
		$a_81_7 = {6e 65 74 2f 75 72 6c 2e 28 2a 55 52 4c 29 2e 48 6f 73 74 6e 61 6d 65 } //1 net/url.(*URL).Hostname
		$a_81_8 = {6e 65 74 2f 75 72 6c 2e 28 2a 55 52 4c 29 2e 50 6f 72 74 } //1 net/url.(*URL).Port
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}