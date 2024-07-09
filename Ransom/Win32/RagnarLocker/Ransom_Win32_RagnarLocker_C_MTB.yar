
rule Ransom_Win32_RagnarLocker_C_MTB{
	meta:
		description = "Ransom:Win32/RagnarLocker.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 0c 57 42 81 f1 ?? ?? ?? ?? 03 f1 8b c6 c1 c0 ?? 2b f0 3b d3 7c e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}