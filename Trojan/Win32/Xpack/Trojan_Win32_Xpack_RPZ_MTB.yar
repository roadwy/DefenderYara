
rule Trojan_Win32_Xpack_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Xpack.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 0c 89 e6 89 46 04 c7 46 08 04 01 00 00 c7 06 00 00 00 00 8b 35 ?? ?? ?? ?? 89 85 b8 fe ff ff 89 8d b4 fe ff ff ff d6 83 ec 08 89 e1 8b 95 f0 fe ff ff 89 51 04 8b b5 b8 fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}