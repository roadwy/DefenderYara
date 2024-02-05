
rule Trojan_Win32_AgentCrypt_SM_MTB{
	meta:
		description = "Trojan:Win32/AgentCrypt.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8d 64 24 90 01 01 50 e8 00 00 00 00 58 83 c0 90 01 01 89 45 90 01 01 58 8d 45 90 01 01 e8 90 01 04 8b 45 90 01 01 8b 00 89 45 90 01 01 8b 45 90 01 01 8b 40 90 01 01 89 45 90 00 } //02 00 
		$a_03_1 = {6a 40 68 00 30 00 00 ff 75 90 01 01 6a 00 ff 55 90 01 01 89 45 90 01 01 ff 75 90 01 01 8b 4d 90 01 01 8b 55 90 01 01 8b 45 90 01 01 e8 90 01 01 ff ff ff 8d 55 90 01 01 8b 45 90 01 01 e8 90 01 04 c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}