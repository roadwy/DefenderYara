
rule Trojan_Win32_Dridex_ACD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ACD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4c 8b d9 0f b6 d2 49 b9 01 01 01 01 01 01 01 01 4c 0f af ca 49 83 f8 10 0f 86 f2 00 00 00 66 49 0f 6e c1 66 0f 60 c0 49 81 f8 80 00 00 00 77 10 0f ba 25 e8 bb 04 00 02 } //03 00 
		$a_80_1 = {57 61 69 74 46 6f 72 54 68 72 65 61 64 70 6f 6f 6c 54 69 6d 65 72 43 61 6c 6c 62 61 63 6b 73 } //WaitForThreadpoolTimerCallbacks  03 00 
		$a_80_2 = {46 6c 75 73 68 50 72 6f 63 65 73 73 57 72 69 74 65 42 75 66 66 65 72 73 } //FlushProcessWriteBuffers  03 00 
		$a_80_3 = {41 63 71 75 69 72 65 53 52 57 4c 6f 63 6b 45 78 63 6c 75 73 69 76 65 } //AcquireSRWLockExclusive  00 00 
	condition:
		any of ($a_*)
 
}