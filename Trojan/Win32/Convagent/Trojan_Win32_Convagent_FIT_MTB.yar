
rule Trojan_Win32_Convagent_FIT_MTB{
	meta:
		description = "Trojan:Win32/Convagent.FIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 64 89 44 24 0c 83 6c 24 0c 90 01 01 8a 54 24 0c 8b 44 24 10 30 14 30 83 ff 0f 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}