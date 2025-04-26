
rule Trojan_Win32_Smokeloader_AAT_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.AAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e0 04 03 45 dc 8d 1c 0e 33 c3 33 45 ?? 81 c6 47 86 c8 61 2b d0 ff 4d f0 89 55 f4 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}