
rule Ransom_Win32_WhisperGate_MFP_MTB{
	meta:
		description = "Ransom:Win32/WhisperGate.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {eb 00 8c c8 8e d8 be 88 7c e8 00 00 50 fc 8a 04 3c 00 74 06 e8 05 00 46 eb f4 eb 05 b4 0e cd 10 } //1
		$a_81_1 = {5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //1 \PhysicalDrive0
		$a_81_2 = {59 6f 75 72 20 68 61 72 64 20 64 72 69 76 65 20 68 61 73 20 62 65 65 6e 20 63 6f 72 72 75 70 74 65 64 } //1 Your hard drive has been corrupted
		$a_81_3 = {62 69 74 63 6f 69 6e 20 77 61 6c 6c 65 74 } //1 bitcoin wallet
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}