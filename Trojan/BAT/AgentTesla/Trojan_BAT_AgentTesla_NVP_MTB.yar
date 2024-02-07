
rule Trojan_BAT_AgentTesla_NVP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {73 66 68 6a 66 6b 66 68 66 68 6a 73 72 66 68 64 68 66 66 61 64 73 66 73 66 68 73 73 63 66 67 64 62 } //03 00  sfhjfkfhfhjsrfhdhffadsfsfhsscfgdb
		$a_81_1 = {66 68 68 66 67 73 66 72 66 6b 66 63 64 73 68 68 66 64 61 73 64 66 68 } //03 00  fhhfgsfrfkfcdshhfdasdfh
		$a_81_2 = {68 66 73 6b 66 64 68 66 73 68 73 65 66 61 66 66 66 64 63 68 } //03 00  hfskfdhfshsefafffdch
		$a_81_3 = {67 64 64 64 66 64 73 66 64 68 66 73 73 66 64 67 68 } //01 00  gdddfdsfdhfssfdgh
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}