
rule Trojan_Win32_Convagent_BAB_MTB{
	meta:
		description = "Trojan:Win32/Convagent.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 07 00 00 00 c1 c0 04 24 0f 04 41 88 06 46 e2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}