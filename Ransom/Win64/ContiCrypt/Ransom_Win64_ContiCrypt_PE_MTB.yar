
rule Ransom_Win64_ContiCrypt_PE_MTB{
	meta:
		description = "Ransom:Win64/ContiCrypt.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6e 74 69 5f 76 33 2e 64 6c 6c } //1 conti_v3.dll
		$a_03_1 = {33 c9 8a 44 0d ?? 0f b6 c0 83 e8 ?? 6b c0 ?? 99 f7 fb 8d ?? ?? 99 f7 fb 88 54 0d ?? 41 83 f9 ?? 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}