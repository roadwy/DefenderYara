
rule Trojan_Win32_RedLine_RDBW_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 84 3d e8 fe ff ff 03 c2 0f b6 c0 0f b6 84 05 e8 fe ff ff 32 86 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}