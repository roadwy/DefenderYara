
rule Ransom_Win64_ContiCrypt_PE_MTB{
	meta:
		description = "Ransom:Win64/ContiCrypt.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6e 74 69 5f 76 33 2e 64 6c 6c } //01 00  conti_v3.dll
		$a_03_1 = {33 c9 8a 44 0d 90 01 01 0f b6 c0 83 e8 90 01 01 6b c0 90 01 01 99 f7 fb 8d 90 01 02 99 f7 fb 88 54 0d 90 01 01 41 83 f9 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}