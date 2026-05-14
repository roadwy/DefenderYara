
rule Ransom_Win64_LockBit_PI_MTB{
	meta:
		description = "Ransom:Win64/LockBit.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 61 00 64 00 4d 00 65 00 46 00 6f 00 72 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 71 00 72 00 } //1 ReadMeForDecryptqr
		$a_03_1 = {48 31 c2 48 89 d0 48 c1 e8 07 48 31 d0 48 89 c2 48 c1 e2 11 48 31 c2 48 89 15 ?? ?? ?? ?? ba 00 10 00 00 e8 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*3) >=4
 
}