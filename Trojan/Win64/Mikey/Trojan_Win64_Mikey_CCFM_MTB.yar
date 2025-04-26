
rule Trojan_Win64_Mikey_CCFM_MTB{
	meta:
		description = "Trojan:Win64/Mikey.CCFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {21 c9 89 8c 24 ?? ?? ?? ?? 4c 89 5c 24 50 66 8b 44 24 1e 66 83 f0 ff 66 89 84 24 ?? ?? ?? ?? 4c 89 b4 24 ?? ?? ?? ?? 8b 4c 24 20 69 c9 ?? ?? ?? ?? 89 8c 24 ?? ?? ?? ?? 4d 39 c3 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}