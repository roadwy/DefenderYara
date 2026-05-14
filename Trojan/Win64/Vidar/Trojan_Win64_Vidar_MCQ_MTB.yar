
rule Trojan_Win64_Vidar_MCQ_MTB{
	meta:
		description = "Trojan:Win64/Vidar.MCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 4d 7a 56 74 59 6a 4d 2d 5a 63 4f 71 32 6a 30 5f 52 48 6f 2f 62 44 49 65 4f 2d 45 6d 63 41 44 32 50 5a 70 4f 4a 49 33 54 2f 5a 73 74 } //1 CMzVtYjM-ZcOq2j0_RHo/bDIeO-EmcAD2PZpOJI3T/Zst
	condition:
		((#a_01_0  & 1)*1) >=1
 
}