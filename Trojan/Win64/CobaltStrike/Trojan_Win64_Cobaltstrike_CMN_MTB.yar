
rule Trojan_Win64_Cobaltstrike_CMN_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.CMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 ff c0 89 44 24 20 48 8b 44 24 28 0f b7 40 06 39 44 24 20 7d 4a 48 8b 44 24 40 8b 40 10 48 8b 4c 24 40 8b 49 14 48 03 4c 24 30 48 8b 54 24 40 8b 52 0c 48 03 54 24 38 48 89 54 24 58 44 8b c0 48 8b d1 48 8b 44 24 58 48 8b c8 e8 ?? ?? ?? ?? 48 8b 44 24 40 48 83 c0 28 48 89 44 24 40 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}