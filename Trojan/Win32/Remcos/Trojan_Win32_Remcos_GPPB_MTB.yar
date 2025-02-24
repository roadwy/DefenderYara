
rule Trojan_Win32_Remcos_GPPB_MTB{
	meta:
		description = "Trojan:Win32/Remcos.GPPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 1f 00 81 f3 ?? ?? ?? ?? 0f 1f 00 0f 1f 00 0f 1f 00 0f 72 f0 ?? 0f 1f 00 0f 1f 00 0f 1f 00 0f 1f 00 0f 1f 00 0f 1f 00 0f 6f c8 0f 1f 00 0f 1f 00 0f 1f 00 0f 1f 00 0f 1f 00 0f 1f 00 66 0f e8 f6 0f 1f 00 0f 1f 00 0f 1f 00 89 1c 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}