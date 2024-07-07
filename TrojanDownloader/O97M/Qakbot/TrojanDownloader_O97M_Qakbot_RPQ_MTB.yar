
rule TrojanDownloader_O97M_Qakbot_RPQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.RPQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 65 74 64 72 64 2e 4f 4f 4f 4f 43 43 43 43 58 58 58 58 } //1 Cetdrd.OOOOCCCCXXXX
		$a_01_1 = {52 65 67 73 76 72 33 32 } //1 Regsvr32
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}