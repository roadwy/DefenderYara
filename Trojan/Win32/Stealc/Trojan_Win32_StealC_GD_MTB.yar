
rule Trojan_Win32_StealC_GD_MTB{
	meta:
		description = "Trojan:Win32/StealC.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c1 33 45 fc 89 45 ec 8b 45 ec 29 45 f8 81 c7 47 86 c8 61 83 6d f0 01 0f 85 ?? ?? ?? ?? 8b 45 08 8b 55 f8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}