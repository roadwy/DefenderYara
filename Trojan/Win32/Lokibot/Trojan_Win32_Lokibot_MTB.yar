
rule Trojan_Win32_Lokibot_MTB{
	meta:
		description = "Trojan:Win32/Lokibot!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f 62 de 49 84 f6 49 38 f6 49 66 39 c1 49 0f 71 f5 ?? 8b 1c 0f 66 0f 66 e9 f6 c4 ?? 53 66 81 fe ?? ?? 3d ?? ?? ?? ?? 38 f6 39 c9 66 85 c9 31 34 24 38 db f7 c3 ?? ?? ?? ?? 38 c8 85 d0 0f 75 c8 0f e2 c4 66 f7 c1 ?? ?? 85 d8 66 0f 73 f3 ?? 66 85 d2 8f 04 08 38 e5 84 c3 38 d0 83 f9 ?? 7f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}