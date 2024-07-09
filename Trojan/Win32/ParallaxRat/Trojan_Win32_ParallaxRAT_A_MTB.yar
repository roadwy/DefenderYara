
rule Trojan_Win32_ParallaxRAT_A_MTB{
	meta:
		description = "Trojan:Win32/ParallaxRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe c3 f7 db 81 c3 ?? ?? ?? ?? f7 db f7 db f6 d3 f6 d3 fe c3 33 ff ff cb 29 9d ?? ?? ff ff c0 e3 ?? 66 81 ?? ?? ?? c0 eb ?? f7 db f6 d3 81 f3 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}