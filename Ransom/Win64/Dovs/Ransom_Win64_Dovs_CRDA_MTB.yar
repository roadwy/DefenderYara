
rule Ransom_Win64_Dovs_CRDA_MTB{
	meta:
		description = "Ransom:Win64/Dovs.CRDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 74 61 72 67 65 74 5c 72 65 6c 65 61 73 65 5c 64 65 70 73 5c 72 63 72 79 70 74 2e 70 64 62 } //01 00  \target\release\deps\rcrypt.pdb
		$a_01_1 = {43 6f 6e 74 65 6e 74 2d 52 61 6e 67 65 43 68 75 6e 6b 20 20 75 70 6c 6f 61 64 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 21 } //00 00  Content-RangeChunk  uploaded successfully!
	condition:
		any of ($a_*)
 
}