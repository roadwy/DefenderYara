
rule Trojan_Win64_Angosay_C_dll{
	meta:
		description = "Trojan:Win64/Angosay.C!dll,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {5c 45 78 74 72 61 63 74 65 64 42 75 6e 64 6c 65 5c 52 54 4d 5f 49 6d 61 67 65 4d 6f 64 52 65 63 5f 31 2e 31 2e 35 2e 30 5f 78 36 34 5c 52 54 4d 5f 49 6d 61 67 65 4d 6f 64 52 65 63 2e 70 64 62 } //1 \ExtractedBundle\RTM_ImageModRec_1.1.5.0_x64\RTM_ImageModRec.pdb
		$a_01_1 = {52 65 73 6f 6c 76 65 4c 6f 63 61 6c 65 4e 61 6d 65 } //1 ResolveLocaleName
		$a_01_2 = {49 73 56 61 6c 69 64 4c 6f 63 61 6c 65 4e 61 6d 65 } //1 IsValidLocaleName
		$a_01_3 = {52 68 70 43 6f 70 79 41 6e 79 57 69 74 68 57 72 69 74 65 42 61 72 72 69 65 72 } //1 RhpCopyAnyWithWriteBarrier
		$a_01_4 = {52 68 70 43 68 65 63 6b 65 64 4c 6f 63 6b 43 6d 70 58 63 68 67 } //1 RhpCheckedLockCmpXchg
		$a_01_5 = {52 68 70 41 73 73 69 67 6e 52 65 66 45 44 58 } //1 RhpAssignRefEDX
		$a_01_6 = {52 65 61 64 46 69 6c 65 } //1 ReadFile
		$a_01_7 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
		$a_01_8 = {46 69 6e 64 43 6c 6f 73 65 } //1 FindClose
		$a_01_9 = {47 65 74 46 69 6c 65 54 79 70 65 } //1 GetFileType
		$a_01_10 = {53 65 74 45 6e 64 4f 66 46 69 6c 65 } //1 SetEndOfFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}