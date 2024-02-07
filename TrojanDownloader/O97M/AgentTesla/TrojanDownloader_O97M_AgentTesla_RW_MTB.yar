
rule TrojanDownloader_O97M_AgentTesla_RW_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 74 6f 70 76 61 6c 75 61 74 69 6f 6e 66 69 72 6d 73 2e 63 6f 6d 2f 6a 61 68 61 68 2e 70 6e 67 } //01 00  //topvaluationfirms.com/jahah.png
		$a_01_1 = {77 73 63 72 69 70 74 2e 73 68 65 6c 6c } //00 00  wscript.shell
	condition:
		any of ($a_*)
 
}