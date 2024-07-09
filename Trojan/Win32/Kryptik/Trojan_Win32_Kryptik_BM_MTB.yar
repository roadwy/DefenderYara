
rule Trojan_Win32_Kryptik_BM_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 74 38 03 88 b5 fb ?? ?? ?? 8a d6 8a 8d fb ?? ?? ?? 80 e2 f0 80 e6 fc c0 e1 06 0a 4c 38 02 c0 e2 02 0a 14 38 c0 e6 04 0a 74 38 01 81 3d ?? ?? ?? ?? be 00 00 00 88 8d fb ?? ?? ?? 8b 8d ec ?? ?? ?? 88 95 fa ?? ?? ?? 88 b5 f9 ?? ?? ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}