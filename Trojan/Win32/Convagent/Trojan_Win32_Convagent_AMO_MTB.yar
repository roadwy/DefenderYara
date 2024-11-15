
rule Trojan_Win32_Convagent_AMO_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 ca 8b 45 ?? c1 e8 05 89 45 ?? 8b 45 ?? 33 f1 8b 4d ?? 03 c1 33 c6 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}