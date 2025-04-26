
rule Trojan_Win32_Windigo_GMK_MTB{
	meta:
		description = "Trojan:Win32/Windigo.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d ?? 03 cf 03 d3 03 45 ?? 81 c3 ?? ?? ?? ?? 33 c1 33 c2 29 45 ?? ff 4d ?? 89 45 ?? 0f 85 ?? ?? ?? ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}