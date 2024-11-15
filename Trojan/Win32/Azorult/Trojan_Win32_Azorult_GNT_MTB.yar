
rule Trojan_Win32_Azorult_GNT_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 ca 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 33 f1 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}