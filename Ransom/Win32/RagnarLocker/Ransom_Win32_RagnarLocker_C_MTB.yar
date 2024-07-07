
rule Ransom_Win32_RagnarLocker_C_MTB{
	meta:
		description = "Ransom:Win32/RagnarLocker.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 0c 57 42 81 f1 90 01 04 03 f1 8b c6 c1 c0 90 01 01 2b f0 3b d3 7c e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}