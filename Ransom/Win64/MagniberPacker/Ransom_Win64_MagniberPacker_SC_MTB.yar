
rule Ransom_Win64_MagniberPacker_SC_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 03 dd e9 bc ?? ?? ?? ?? ?? ?? ?? e3 23 88 ?? ?? ?? ?? 03 6d ?? 7b ?? c3 32 ae ?? ?? ?? ?? e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? fb 04 ?? 94 6a ?? 31 b0 ?? ?? ?? ?? a1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}