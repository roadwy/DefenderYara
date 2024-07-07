
rule Trojan_Win32_CobaltStrike_LKBD_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.LKBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 88 00 90 01 03 83 f1 90 01 01 83 f1 90 01 01 83 f1 90 01 01 83 f1 90 01 01 8b 95 90 01 02 ff ff 88 8a 90 01 04 8b 85 90 01 02 ff ff 83 c0 01 89 85 90 01 02 ff ff eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}