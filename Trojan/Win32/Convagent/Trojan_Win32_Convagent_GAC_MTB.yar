
rule Trojan_Win32_Convagent_GAC_MTB{
	meta:
		description = "Trojan:Win32/Convagent.GAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 43 ef 6d 00 ba ?? ?? ?? ?? be ?? ?? ?? ?? 49 b9 ?? ?? ?? ?? 00 0a 01 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}