
rule Ransom_Win64_Tuga_SKH_MTB{
	meta:
		description = "Ransom:Win64/Tuga.SKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 54 75 67 61 2e 65 78 65 } //1 RansomTuga.exe
		$a_01_1 = {73 74 61 74 65 20 6e 6f 74 20 72 65 63 6f 76 65 72 61 62 6c 65 } //1 state not recoverable
		$a_01_2 = {6f 77 6e 65 72 20 64 65 61 64 } //1 owner dead
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}