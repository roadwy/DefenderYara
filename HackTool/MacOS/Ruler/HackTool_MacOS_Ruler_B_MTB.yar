
rule HackTool_MacOS_Ruler_B_MTB{
	meta:
		description = "HackTool:MacOS/Ruler.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 73 65 6e 73 65 70 6f 73 74 2f 72 75 6c 65 72 2f 6d 61 70 69 } //1 github.com/sensepost/ruler/mapi
		$a_00_1 = {72 75 6c 65 72 2f 72 70 63 2d 68 74 74 70 2f 70 61 63 6b 65 74 73 2e 67 6f } //1 ruler/rpc-http/packets.go
		$a_00_2 = {61 75 74 6f 64 69 73 63 6f 76 65 72 2f 62 72 75 74 65 2e 67 6f } //1 autodiscover/brute.go
		$a_00_3 = {2f 72 75 6c 65 72 2f 61 75 74 6f 64 69 73 63 6f 76 65 72 2e 55 73 65 72 50 61 73 73 42 72 75 74 65 46 6f 72 63 65 } //1 /ruler/autodiscover.UserPassBruteForce
		$a_00_4 = {2a 74 6c 73 2e 63 6c 69 65 6e 74 4b 65 79 45 78 63 68 61 6e 67 65 4d 73 67 } //1 *tls.clientKeyExchangeMsg
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}