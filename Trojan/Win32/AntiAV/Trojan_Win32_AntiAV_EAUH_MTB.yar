
rule Trojan_Win32_AntiAV_EAUH_MTB{
	meta:
		description = "Trojan:Win32/AntiAV.EAUH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c2 89 84 24 d0 02 00 00 89 2d ?? ?? ?? ?? 8b 84 24 d0 02 00 00 29 44 24 18 81 3d } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}