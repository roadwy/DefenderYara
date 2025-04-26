
rule Trojan_Win32_ClipBanker_CB_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f0 50 e8 ?? 02 00 00 83 c4 04 89 45 ec 8b 45 ec 83 f8 1a 0f ?? ?? 00 00 00 8b 45 ec 83 f8 23 0f ?? ?? 00 00 00 8b 45 f0 0f be 08 83 f9 31 0f ?? ?? 00 00 00 8b 45 f4 89 45 f0 e8 ?? 02 00 00 8b 45 f0 50 e8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}