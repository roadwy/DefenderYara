
rule Trojan_Win32_GCleaner_KAB_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d0 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 33 ca 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}