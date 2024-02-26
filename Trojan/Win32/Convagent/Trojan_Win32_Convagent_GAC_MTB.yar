
rule Trojan_Win32_Convagent_GAC_MTB{
	meta:
		description = "Trojan:Win32/Convagent.GAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 43 ef 6d 00 ba 90 01 04 be 90 01 04 49 b9 90 01 04 00 0a 01 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}