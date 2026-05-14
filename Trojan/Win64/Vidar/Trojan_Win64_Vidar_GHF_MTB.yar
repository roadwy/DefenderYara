
rule Trojan_Win64_Vidar_GHF_MTB{
	meta:
		description = "Trojan:Win64/Vidar.GHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 32 4d 69 4a ?? 51 67 71 6b 32 32 4d 69 4a ?? 51 67 71 6b 32 32 4d 69 4a ?? 51 67 71 6b 32 32 4d 69 4a ?? 51 67 71 6b 32 32 4d 69 4a ?? 51 67 71 6b 32 32 4d 69 4a ?? 51 67 71 6b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}