
rule Trojan_Win32_Convagent_EGD_MTB{
	meta:
		description = "Trojan:Win32/Convagent.EGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 1c 8b c5 2b cd 8b fe 8a 1c 01 30 18 40 4f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}