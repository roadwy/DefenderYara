
rule Trojan_Win32_ClipBanker_BO_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8b 45 fc 50 e8 ?? ?? ff ff 83 c4 04 0f b6 c8 85 c9 74 ?? 68 ?? ?? 40 00 e8 ?? ?? ff ff 83 c4 04 8b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}