
rule Trojan_BAT_DiscordGrabber_RDA_MTB{
	meta:
		description = "Trojan:BAT/DiscordGrabber.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 21 00 00 0a 0b 07 28 42 00 00 0a 16 fe 01 0c 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}