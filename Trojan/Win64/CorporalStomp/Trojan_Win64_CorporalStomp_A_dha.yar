
rule Trojan_Win64_CorporalStomp_A_dha{
	meta:
		description = "Trojan:Win64/CorporalStomp.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_42_0 = {36 08 fd 00 e8 90 01 02 ff ff ba 1a 44 fd 00 8b f0 e8 90 01 02 ff ff ba eb b2 09 00 89 45 90 01 01 e8 90 01 02 ff ff ba a3 97 fc 00 89 45 90 01 01 e8 90 01 02 ff ff 90 00 00 } //1
	condition:
		((#a_42_0  & 1)*1) >=1
 
}