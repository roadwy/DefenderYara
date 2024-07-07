
rule Trojan_Win32_Dridex_VD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {41 63 71 75 69 72 65 53 52 57 4c 6f 63 6b 45 78 63 6c 75 73 69 76 65 } //AcquireSRWLockExclusive  3
		$a_80_1 = {54 72 79 41 63 71 75 69 72 65 53 52 57 4c 6f 63 6b 45 78 63 6c 75 73 69 76 65 } //TryAcquireSRWLockExclusive  3
		$a_80_2 = {52 65 6c 65 61 73 65 53 52 57 4c 6f 63 6b 45 78 63 6c 75 73 69 76 65 } //ReleaseSRWLockExclusive  3
		$a_80_3 = {46 72 6f 6d 5c 46 61 6d 6f 75 73 5c 77 68 79 5c 74 6f 67 65 74 68 65 72 2e 70 64 62 } //From\Famous\why\together.pdb  3
		$a_80_4 = {41 70 70 65 61 72 6c 65 74 } //Appearlet  3
		$a_80_5 = {48 61 73 6c 6f 74 } //Haslot  3
		$a_80_6 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //IsProcessorFeaturePresent  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}