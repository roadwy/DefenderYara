
rule Trojan_Win32_Jatif_GPN_MTB{
	meta:
		description = "Trojan:Win32/Jatif.GPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 07 0f b6 0e 8b 95 f4 fe ff ff 03 c8 0f b6 c1 8b 8d f0 fe ff ff 8a 84 05 fc fe ff ff 32 04 0a 88 01 41 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}