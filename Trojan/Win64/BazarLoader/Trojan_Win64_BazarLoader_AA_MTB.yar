
rule Trojan_Win64_BazarLoader_AA_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 84 0c ?? ?? ?? ?? 83 e8 [0-04] 6b c0 d4 99 41 f7 f8 8d 42 ?? 99 41 f7 f8 88 94 0c ?? ?? ?? ?? 48 ff c1 48 83 f9 ?? 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}