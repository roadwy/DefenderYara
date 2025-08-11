
rule Ransom_Win64_Crypmod_ARAX_MTB{
	meta:
		description = "Ransom:Win64/Crypmod.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 85 0c 01 00 00 48 63 d0 48 8b 85 ?? ?? ?? ?? 48 01 d0 0f b6 10 8b 85 0c 01 00 00 48 63 c8 48 8b 85 ?? ?? ?? ?? 48 01 c8 83 f2 55 88 10 83 85 0c 01 00 00 ?? 8b 85 0c 01 00 00 3b 85 ?? ?? ?? ?? 7c bd } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}