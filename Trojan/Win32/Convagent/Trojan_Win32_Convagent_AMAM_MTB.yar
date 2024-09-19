
rule Trojan_Win32_Convagent_AMAM_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AMAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 34 88 8b 4a ?? 8b 44 24 ?? 8a 04 01 b9 ?? ?? ?? ?? 30 04 2e e8 ?? ?? ?? ?? 50 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}