
rule Trojan_BAT_AgentTesla_SJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 08 17 58 13 06 07 08 07 08 91 28 15 00 00 06 08 1f 16 5d 91 61 07 11 06 09 5d 91 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 08 17 58 0c 00 08 09 fe 04 13 07 11 07 2d c6 } //2
		$a_81_1 = {46 6f 6c 64 65 72 53 65 61 72 63 68 65 72 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //2 FolderSearcher.Form1.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}