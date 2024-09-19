
rule Trojan_Win32_ClipBanker_CE_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 02 8b f1 c6 85 cb fc ff ff 00 c7 85 cc fc ff ff 2c 02 00 00 ff 15 ?? 00 02 10 8b f8 8d 85 cc fc ff ff 50 57 ff 15 ?? 00 02 10 85 ?? 74 63 53 8b 1d ?? 00 02 10 0f 1f 00 6a 00 6a 00 68 04 01 00 00 8d 85 f8 fe ff ff 50 6a ff 8d 85 f0 fc ff ff 50 6a 00 6a 00 ff 15 ?? 00 02 10 83 7e 14 0f 8b c6 76 ?? 8b 06 50 8d 85 f8 fe ff ff 50 e8 ?? ?? 00 00 83 c4 08 85 c0 74 10 8d 85 cc fc ff ff 50 57 ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}