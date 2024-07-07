
rule HackTool_Linux_Ruler_A_MTB{
	meta:
		description = "HackTool:Linux/Ruler.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 64 69 73 63 6f 76 65 72 2e 42 72 75 74 65 46 6f 72 63 65 } //1 autodiscover.BruteForce
		$a_01_1 = {2f 64 65 76 2f 72 75 6c 65 72 2f 72 75 6c 65 72 2e 67 6f } //1 /dev/ruler/ruler.go
		$a_01_2 = {2f 72 70 63 2d 68 74 74 70 2f 70 61 63 6b 65 74 73 2e 67 6f } //1 /rpc-http/packets.go
		$a_01_3 = {67 69 74 68 75 62 2e 63 6f 6d 2f 73 65 6e 73 65 70 6f 73 74 2f 72 75 6c 65 72 2f 6d 61 70 69 2e 45 78 65 63 75 74 65 4d 61 69 6c 52 75 6c 65 41 64 64 } //1 github.com/sensepost/ruler/mapi.ExecuteMailRuleAdd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}