
rule Trojan_Win32_Trickbot_DSA_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {55 8b ec b8 18 2c 00 00 e8 90 01 04 a1 90 01 04 33 c5 89 45 fc c6 85 fc d3 ff ff 90 01 01 c6 85 fd d3 ff ff 90 01 01 c6 85 fe d3 ff ff 90 01 01 c6 85 ff d3 ff ff 90 01 01 c6 85 00 d4 ff ff 90 01 01 c6 85 01 d4 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}