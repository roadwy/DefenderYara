
rule Trojan_Win32_Cryptinject_PY_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.PY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 18 2a da 8b 15 ?? ?? ?? ?? 80 eb 06 0f b7 f8 8d 86 68 f5 02 01 8b 74 24 10 83 44 24 10 04 a3 ?? ?? ?? ?? 89 06 0f b6 c3 66 2b 05 ?? ?? ?? ?? 83 6c 24 1c 01 8d 34 07 66 8b c6 0f b7 fe 89 44 24 0c 0f 85 ?? ?? ?? ?? 8d 82 3e 58 00 00 03 c6 81 3d ?? ?? ?? ?? 44 10 00 00 66 a3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}