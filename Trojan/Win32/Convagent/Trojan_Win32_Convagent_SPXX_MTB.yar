
rule Trojan_Win32_Convagent_SPXX_MTB{
	meta:
		description = "Trojan:Win32/Convagent.SPXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ec 04 08 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 00 08 00 00 a1 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 9e 13 00 00 a3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}