
rule Trojan_AndroidOS_SAgnt_G_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 61 74 61 48 75 62 2f 64 65 76 69 63 65 4a 2f 73 74 73 } //01 00  DataHub/deviceJ/sts
		$a_00_1 = {78 5f 75 70 5f 63 6c 69 65 6e 74 5f 63 68 61 6e 6e 65 6c 5f 69 64 } //01 00  x_up_client_channel_id
		$a_00_2 = {63 6c 74 33 30 2f 74 65 73 74 2e 6a 73 70 } //00 00  clt30/test.jsp
	condition:
		any of ($a_*)
 
}