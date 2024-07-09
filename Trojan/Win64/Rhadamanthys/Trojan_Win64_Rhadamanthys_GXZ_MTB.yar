
rule Trojan_Win64_Rhadamanthys_GXZ_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6b c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 6e c6 44 24 ?? 65 c6 44 24 ?? 6c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 c6 44 24 ?? 6c c6 44 24 ?? 6c c6 44 24 ?? 56 c6 44 24 ?? 69 c6 44 24 ?? 72 c6 44 24 ?? 74 c6 44 24 ?? 75 c6 44 24 ?? 61 c6 44 24 ?? 6c c6 44 24 ?? 41 c6 44 24 ?? 6c c6 44 24 ?? 6c c6 44 24 ?? 6f c6 44 24 ?? 63 41 b8 0c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}