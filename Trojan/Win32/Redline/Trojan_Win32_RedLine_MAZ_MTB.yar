
rule Trojan_Win32_RedLine_MAZ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 5c 24 2c 8b 54 24 38 8b 0c b7 0f b6 04 33 30 04 11 8b 4c 24 ?? 83 f9 ?? 76 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}