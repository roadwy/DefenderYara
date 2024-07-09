
rule TrojanDownloader_BAT_Netwire_ANW_MTB{
	meta:
		description = "TrojanDownloader:BAT/Netwire.ANW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 43 00 00 70 6f ?? ?? ?? 0a 11 02 28 ?? ?? ?? 0a 72 43 00 00 70 6f ?? ?? ?? 0a 8e 69 5d 91 7e 03 00 00 04 11 02 91 61 d2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}