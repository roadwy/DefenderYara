
rule Trojan_Win32_TrickBot_A_ibt{
	meta:
		description = "Trojan:Win32/TrickBot.A!ibt,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 72 64 70 73 63 61 6e 2e 70 64 62 } //02 00  \rdpscan.pdb
		$a_01_1 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 } //00 00  潃瑮潲l牆敥畂晦牥刀汥慥敳匀慴瑲
	condition:
		any of ($a_*)
 
}