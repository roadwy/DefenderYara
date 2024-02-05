
rule Trojan_MacOS_UpdateAgent_A_MTB{
	meta:
		description = "Trojan:MacOS/UpdateAgent.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 89 e5 48 83 ec 20 89 7d fc 48 89 75 f0 8b 7d fc e8 90 01 03 00 83 f8 00 0f 90 01 04 00 48 90 01 04 00 00 48 63 4d fc 8b 54 88 3c 89 d0 48 23 45 f0 48 83 f8 00 40 0f 95 c6 40 80 f6 ff 40 80 f6 ff 40 88 75 ef 90 00 } //02 00 
		$a_00_1 = {89 ca 48 8d bd 68 ff ff ff 48 8d b5 60 ff ff ff 48 89 95 f8 fd ff ff e8 d2 06 00 00 48 8d 45 88 48 89 c7 48 89 85 f0 fd ff ff e8 6f 06 00 00 48 89 85 38 ff ff ff 48 8d bd 40 ff ff ff 48 8d b5 38 ff ff ff 48 8b 95 f8 fd ff ff e8 9e 06 00 00 48 8b b5 68 ff ff ff 48 8b 95 40 ff ff ff 48 8b bd f0 fd ff ff e8 94 04 00 00 48 89 85 e8 fd ff ff e9 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}