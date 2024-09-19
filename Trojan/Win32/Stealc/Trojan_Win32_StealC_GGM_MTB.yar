
rule Trojan_Win32_StealC_GGM_MTB{
	meta:
		description = "Trojan:Win32/StealC.GGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 64 89 85 f8 fb ff ff 83 ad ?? ?? ?? ?? 64 8a 85 f8 fb ff ff 30 04 33 83 7d 08 0f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}