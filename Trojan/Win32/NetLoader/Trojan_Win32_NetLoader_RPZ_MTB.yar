
rule Trojan_Win32_NetLoader_RPZ_MTB{
	meta:
		description = "Trojan:Win32/NetLoader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a cb 32 4d fb 89 45 bc 8b 45 08 88 4c 15 f4 8b 0d 90 01 04 88 44 0d f5 85 f6 74 08 8a 55 f4 88 14 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}