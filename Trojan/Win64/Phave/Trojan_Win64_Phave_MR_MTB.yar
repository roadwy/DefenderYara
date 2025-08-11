
rule Trojan_Win64_Phave_MR_MTB{
	meta:
		description = "Trojan:Win64/Phave.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 c1 48 8b 05 ?? ?? 00 00 ff d0 48 89 85 ?? ?? 00 00 48 83 bd ?? ?? 00 00 00 75 0a b8 01 00 00 00 e9 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 48 8d 15 ?? ?? 00 00 48 89 c1 48 8b 05 ?? ?? 00 00 ff d0 } //5
		$a_03_1 = {48 01 d0 0f b6 00 48 8b 8d ?? ?? 00 00 48 8b 95 ?? ?? 00 00 48 01 ca 32 85 ?? ?? 00 00 88 02 48 83 85 } //10
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*10) >=15
 
}