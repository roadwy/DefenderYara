
rule Trojan_Win64_Bumblebee_VIR_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.VIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 8d 1c 08 4d 2b e8 4c 89 1c 24 49 8b f0 4c 89 ac 24 ?? ?? ?? ?? 44 0f b7 44 24 ?? 48 2b d9 43 8a 0c 2b 2a 8c 24 ?? ?? ?? ?? 32 8c 24 ?? ?? ?? ?? 49 8b 41 ?? 41 88 0c 03 83 ff 08 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}