
rule Ransom_Win64_LockBit_PJ_MTB{
	meta:
		description = "Ransom:Win64/LockBit.PJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 00 25 00 64 00 5d 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 3a 00 } //1 [%d] Encrypted:
		$a_01_1 = {5c 00 64 00 65 00 66 00 72 00 61 00 67 00 2e 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 } //1 \defrag.\svchost
		$a_01_2 = {52 00 65 00 61 00 64 00 4d 00 65 00 46 00 6f 00 72 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 71 00 72 00 } //3 ReadMeForDecryptqr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}