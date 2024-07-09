
rule Trojan_Win32_IcedID_PVE_MTB{
	meta:
		description = "Trojan:Win32/IcedID.PVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 03 de 66 89 15 ?? ?? ?? ?? 8b 74 24 18 66 89 1d ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 81 c3 ac f5 ff ff 89 06 90 09 05 00 a3 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}