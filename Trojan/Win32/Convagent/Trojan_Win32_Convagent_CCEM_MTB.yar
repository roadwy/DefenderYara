
rule Trojan_Win32_Convagent_CCEM_MTB{
	meta:
		description = "Trojan:Win32/Convagent.CCEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f a4 c9 0e 0f b6 82 ?? ?? ?? ?? 33 c1 88 04 14 42 0f be d2 83 fa } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}