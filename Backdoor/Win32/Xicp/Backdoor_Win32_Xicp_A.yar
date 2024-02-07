
rule Backdoor_Win32_Xicp_A{
	meta:
		description = "Backdoor:Win32/Xicp.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 38 00 34 00 44 00 34 00 43 00 34 00 34 00 2d 00 45 00 33 00 30 00 34 00 2d 00 34 00 31 00 61 00 64 00 2d 00 38 00 45 00 44 00 45 00 2d 00 46 00 32 00 36 00 31 00 38 00 44 00 43 00 43 00 33 00 36 00 30 00 35 00 } //01 00  C84D4C44-E304-41ad-8EDE-F2618DCC3605
		$a_01_1 = {4e 00 65 00 74 00 66 00 69 00 6c 00 74 00 65 00 72 00 } //01 00  Netfilter
		$a_01_2 = {6d 63 64 6f 6e 61 6c 64 73 73 2e 78 69 63 70 2e 6e 65 74 } //01 00  mcdonaldss.xicp.net
		$a_01_3 = {57 6f 72 6b 4d 61 69 6e } //00 00  WorkMain
	condition:
		any of ($a_*)
 
}