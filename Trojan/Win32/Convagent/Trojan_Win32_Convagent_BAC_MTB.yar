
rule Trojan_Win32_Convagent_BAC_MTB{
	meta:
		description = "Trojan:Win32/Convagent.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8d 0c 1a 8d 42 01 42 30 01 81 fa ?? ?? ?? ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}