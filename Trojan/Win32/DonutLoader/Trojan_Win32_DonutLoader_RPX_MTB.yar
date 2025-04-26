
rule Trojan_Win32_DonutLoader_RPX_MTB{
	meta:
		description = "Trojan:Win32/DonutLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff d0 89 85 7c 02 00 00 48 8b 85 90 02 00 00 48 8b 80 f0 00 00 00 48 8b 95 58 02 00 00 48 89 d1 ff d0 48 8b 85 90 02 00 00 48 8b 80 f0 00 00 00 48 8b 95 60 02 00 00 48 89 d1 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}