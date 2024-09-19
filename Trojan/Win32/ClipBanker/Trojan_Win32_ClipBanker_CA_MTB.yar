
rule Trojan_Win32_ClipBanker_CA_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 55 f7 8d 45 d4 89 14 24 89 c1 e8 ?? ?? 00 00 83 ec 04 8d 45 dc 8d 55 d4 89 14 24 89 c1 e8 ?? ?? 00 00 83 ec 04 8d 45 dc 89 04 24 8b 4d 08 e8 ?? ?? 00 00 83 ec 04 8d 45 dc 89 c1 e8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}