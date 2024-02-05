
rule Trojan_Win64_CoinMiner_AMT_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {fa 25 33 00 16 00 00 01 00 00 00 01 00 00 00 02 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 } //03 00 
		$a_80_1 = {63 3a 5c 77 69 6e 64 6f } //c:\windo  03 00 
		$a_80_2 = {6d 33 32 5c 63 6d } //m32\cm  03 00 
		$a_80_3 = {64 2e 65 78 65 } //d.exe  03 00 
		$a_80_4 = {41 63 71 75 69 72 65 53 52 57 4c 6f 63 6b 45 78 63 6c 75 73 69 76 65 } //AcquireSRWLockExclusive  03 00 
		$a_80_5 = {6e 77 67 6f 6c 64 5f 66 61 73 74 5f } //nwgold_fast_  03 00 
		$a_80_6 = {43 72 65 61 74 65 53 79 6d 62 6f 6c 69 63 4c 69 6e 6b 57 } //CreateSymbolicLinkW  00 00 
	condition:
		any of ($a_*)
 
}