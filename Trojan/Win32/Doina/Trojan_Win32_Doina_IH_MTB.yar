
rule Trojan_Win32_Doina_IH_MTB{
	meta:
		description = "Trojan:Win32/Doina.IH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 35 ?? ?? ?? ?? 03 c8 0f b6 c1 8b 8d ?? ?? ?? ?? 0f b6 84 05 ?? ?? ?? ?? 32 44 1a ?? 88 04 11 42 81 fa ?? ?? ?? ?? 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}