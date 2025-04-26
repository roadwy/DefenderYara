
rule Trojan_Win32_Convagent_AMAI_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AMAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0c 86 0f b6 04 07 6a ?? 30 04 11 b9 ?? ?? ?? ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}