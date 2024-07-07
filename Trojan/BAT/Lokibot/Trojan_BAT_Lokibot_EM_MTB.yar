
rule Trojan_BAT_Lokibot_EM_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {54 77 6d 66 64 63 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Twmfdc.Properties.Resources
		$a_81_1 = {2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 } //1 //cdn.discordapp.com/attachments
		$a_81_2 = {2f 63 20 70 69 6e 67 20 79 61 68 6f 6f 2e 63 6f 6d } //1 /c ping yahoo.com
		$a_81_3 = {59 76 64 72 7a 73 73 73 6b 78 74 61 6b 70 6d 6c 66 6e } //1 Yvdrzssskxtakpmlfn
		$a_81_4 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_5 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}