
rule Trojan_Win32_Emotet_DEX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 fa f7 f1 8b 8c 24 ?? ?? ?? ?? 80 c3 01 03 8c 24 90 1b 00 8b 3d ?? ?? ?? ?? 89 8c 24 90 1b 00 8a 3c 17 8b 4c 24 2c 8b 54 24 04 8a 0c 11 28 f9 8b 7c 24 28 88 0c 17 30 fb 8b 0c 24 88 5c 0c 37 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}