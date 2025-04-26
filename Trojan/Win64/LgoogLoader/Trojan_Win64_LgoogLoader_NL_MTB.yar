
rule Trojan_Win64_LgoogLoader_NL_MTB{
	meta:
		description = "Trojan:Win64/LgoogLoader.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 b8 16 00 00 00 e8 89 06 00 00 85 c0 74 14 ff c3 48 63 cb 48 81 f9 ?? ?? ?? ?? 72 dc 48 8b 45 ?? eb 06 48 63 c3 48 03 c7 } //5
		$a_03_1 = {48 85 c0 0f 84 ec 36 00 00 48 8b c8 e8 2b 00 00 00 48 85 c0 0f 84 db 36 00 00 b9 ?? ?? ?? ?? 66 39 48 5c } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}