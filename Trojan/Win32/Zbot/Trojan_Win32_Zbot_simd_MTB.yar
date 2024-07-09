
rule Trojan_Win32_Zbot_simd_MTB{
	meta:
		description = "Trojan:Win32/Zbot.simd!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 0e 8b 45 a8 c1 c0 0c 03 f0 8b 16 c1 c2 03 83 e2 09 03 ca 4b 89 0f b8 ?? ?? ?? ?? 35 fe 0c cd f5 03 f8 85 db 75 b0 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}