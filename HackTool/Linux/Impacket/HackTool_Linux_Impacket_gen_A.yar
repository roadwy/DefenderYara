
rule HackTool_Linux_Impacket_gen_A{
	meta:
		description = "HackTool:Linux/Impacket.gen!A!!Impacket.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {69 6d 70 61 63 6b 65 74 2e 64 63 65 72 70 63 2e 76 35 } //01 00  impacket.dcerpc.v5
		$a_81_1 = {69 6d 70 61 63 6b 65 74 2e 73 6d 62 } //01 00  impacket.smb
		$a_81_2 = {69 6d 70 61 63 6b 65 74 2e 6b 72 62 35 } //01 00  impacket.krb5
		$a_81_3 = {69 6d 70 61 63 6b 65 74 2e 76 65 72 73 69 6f 6e } //01 00  impacket.version
		$a_81_4 = {63 6d 65 2e 63 6f 6e 66 } //00 00  cme.conf
	condition:
		any of ($a_*)
 
}