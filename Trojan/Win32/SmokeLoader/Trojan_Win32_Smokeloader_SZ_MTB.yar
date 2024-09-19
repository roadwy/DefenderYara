
rule Trojan_Win32_Smokeloader_SZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 59 8a 4d ?? 03 c7 30 08 83 7d ?? 0f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}