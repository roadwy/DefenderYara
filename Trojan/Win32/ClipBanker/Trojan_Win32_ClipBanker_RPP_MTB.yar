
rule Trojan_Win32_ClipBanker_RPP_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 fc 8b 4d fc 81 e1 ff 00 00 00 8b 55 08 03 55 f0 8b 45 f8 8a 12 32 14 08 8b 45 08 03 45 f0 88 10 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}