
rule Trojan_Win32_Convagent_RPM_MTB{
	meta:
		description = "Trojan:Win32/Convagent.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 fa 04 89 c8 c1 f8 1f 29 c2 89 d0 ba 4b 00 00 00 0f af c2 89 c1 8b 55 ec 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 ec 01 eb } //00 00 
	condition:
		any of ($a_*)
 
}