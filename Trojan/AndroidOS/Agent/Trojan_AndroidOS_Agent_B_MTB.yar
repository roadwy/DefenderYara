
rule Trojan_AndroidOS_Agent_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Agent.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {21 42 23 21 19 00 12 00 21 42 35 20 10 00 48 02 04 00 21 53 94 03 00 03 48 03 05 03 b7 32 8d 22 4f 02 01 00 d8 00 00 01 28 f0 11 01 } //1
		$a_00_1 = {65 6e 63 6f 64 65 64 46 69 6c 65 42 79 74 65 73 } //1 encodedFileBytes
		$a_00_2 = {6b 69 6c 6c 50 72 6f 63 65 73 73 } //1 killProcess
		$a_00_3 = {77 72 69 74 65 64 44 65 78 46 69 6c 65 } //1 writedDexFile
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}