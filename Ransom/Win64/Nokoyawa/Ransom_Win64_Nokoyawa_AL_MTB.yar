
rule Ransom_Win64_Nokoyawa_AL_MTB{
	meta:
		description = "Ransom:Win64/Nokoyawa.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b c4 41 83 c4 01 49 83 c0 01 99 83 e2 0f 03 c2 83 e0 0f 2b c2 48 63 c8 48 8b 44 ?? ?? 42 0f b6 8c 31 ?? ?? ?? ?? 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 ?? ?? 90 13 41 8b c4 41 83 c4 01 49 83 c0 01 99 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}