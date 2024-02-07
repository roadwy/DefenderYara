
rule TrojanProxy_Win64_Magroxy_A_dha{
	meta:
		description = "TrojanProxy:Win64/Magroxy.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 21 50 53 2d 41 64 6f 62 65 2d } //01 00  %!PS-Adobe-
		$a_01_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 66 61 74 65 64 69 65 72 2f 66 72 70 2f 63 6d 64 2f 66 72 70 63 } //01 00  github.com/fatedier/frp/cmd/frpc
		$a_01_2 = {67 69 74 68 75 62 2e 63 6f 6d 2f 66 61 74 65 64 69 65 72 2f 66 72 70 2f 63 6d 64 2f 66 72 70 63 2f 73 75 62 2e 73 74 61 72 74 53 65 72 76 69 63 65 } //01 00  github.com/fatedier/frp/cmd/frpc/sub.startService
		$a_01_3 = {4d 41 47 41 32 30 32 34 21 21 21 } //01 00  MAGA2024!!!
		$a_01_4 = {48 54 54 50 5f 50 52 4f 58 59 48 6f 73 74 3a 20 25 73 } //00 00  HTTP_PROXYHost: %s
	condition:
		any of ($a_*)
 
}