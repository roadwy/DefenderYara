
rule Trojan_Win32_Smokeloader_GNZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 8a 89 88 c7 45 ?? 8f 8e 8d 8c 66 c7 45 ?? ?? ?? 8a 44 0d c0 34 bb 88 44 0d 80 41 83 f9 3e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}