
rule Trojan_Win32_Dridex_BQ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {2f 72 6e 74 75 72 74 79 6e 75 72 74 79 2e 70 64 62 } ///rnturtynurty.pdb  3
		$a_80_1 = {50 6f 73 74 51 75 69 74 4d 65 73 73 61 67 65 } //PostQuitMessage  3
		$a_80_2 = {52 70 63 53 65 72 76 65 72 55 73 65 41 6c 6c 50 72 6f 74 73 65 71 73 49 66 } //RpcServerUseAllProtseqsIf  3
		$a_80_3 = {57 65 72 41 64 64 45 78 63 6c 75 64 65 64 41 70 70 6c 69 63 61 74 69 6f 6e } //WerAddExcludedApplication  3
		$a_80_4 = {77 65 72 2e 64 6c 6c } //wer.dll  3
		$a_80_5 = {57 65 72 53 79 73 70 72 65 70 47 65 6e 65 72 61 6c 69 7a 65 } //WerSysprepGeneralize  3
		$a_80_6 = {57 65 72 70 41 75 78 6d 64 44 75 6d 70 52 65 67 69 73 74 65 72 65 64 42 6c 6f 63 6b 73 } //WerpAuxmdDumpRegisteredBlocks  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}