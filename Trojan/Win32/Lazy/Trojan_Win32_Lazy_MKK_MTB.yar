
rule Trojan_Win32_Lazy_MKK_MTB{
	meta:
		description = "Trojan:Win32/Lazy.MKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 8a 84 35 dc fe ff ff 88 84 3d dc fe ff ff 88 8c 35 dc fe ff ff 0f b6 84 3d dc fe ff ff 03 c2 8b 55 ?? 0f b6 c0 8a 84 05 dc fe ff ff 30 04 13 43 3b 5d e0 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}