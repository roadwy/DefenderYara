
rule Trojan_Win32_Convagent_BAA_MTB{
	meta:
		description = "Trojan:Win32/Convagent.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 49 0e 2b c1 85 c0 74 ?? a1 ?? ?? ?? ?? 05 88 13 00 00 a3 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}