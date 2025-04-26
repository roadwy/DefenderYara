
rule Ransom_Win32_RagnarLocker_D_MTB{
	meta:
		description = "Ransom:Win32/RagnarLocker.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 f0 8b 0c 0e 01 8c 05 ?? ?? ?? ?? 8b 94 05 90 1b 00 8b ca c1 e9 ?? 88 4e ff 8b ca 88 94 05 ?? ?? ?? ?? 83 c0 ?? c1 e9 ?? c1 ea ?? 88 0e 88 56 01 83 f8 ?? 72 bd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}