
rule TrojanDownloader_BAT_AgentTesla_AW_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 2b 44 2b 45 91 61 d2 6f 90 01 03 0a 07 1d 2c 04 17 58 0b 07 02 8e 69 32 db 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}