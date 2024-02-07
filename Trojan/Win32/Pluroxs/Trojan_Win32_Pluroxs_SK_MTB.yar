
rule Trojan_Win32_Pluroxs_SK_MTB{
	meta:
		description = "Trojan:Win32/Pluroxs.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 6f 6f 67 6c 65 2d 70 75 62 6c 69 63 2d 64 6e 73 2d 61 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //01 00  google-public-dns-a.google.com
		$a_01_1 = {57 69 6e 53 6f 63 6b 20 32 2e 30 } //01 00  WinSock 2.0
		$a_01_2 = {2f 4d 50 47 6f 6f 64 53 74 61 74 75 73 } //01 00  /MPGoodStatus
		$a_01_3 = {45 3a 5c 4f 6c 64 53 6f 66 74 77 61 72 65 5c 47 65 6e 65 72 61 74 69 6e 67 5c 43 72 79 70 74 6f 5c 63 72 79 70 74 6f 2e 70 64 62 } //00 00  E:\OldSoftware\Generating\Crypto\crypto.pdb
	condition:
		any of ($a_*)
 
}