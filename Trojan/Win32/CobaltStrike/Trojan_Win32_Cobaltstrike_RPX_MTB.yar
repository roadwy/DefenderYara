
rule Trojan_Win32_Cobaltstrike_RPX_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 8d 45 f8 50 ff 36 ff d3 3d ?? ?? ?? ?? 74 2c 83 c6 04 83 c7 06 81 fe ?? ?? ?? ?? 7c e2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}