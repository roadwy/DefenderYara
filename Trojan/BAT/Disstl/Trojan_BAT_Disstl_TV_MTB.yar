
rule Trojan_BAT_Disstl_TV_MTB{
	meta:
		description = "Trojan:BAT/Disstl.TV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {0a 26 09 16 28 0a 00 00 0a 20 68 dc 2d 7d 61 1f 64 59 13 04 07 09 16 1a 6f 09 00 00 0a 26 09 16 28 0a 00 00 0a 1b 59 20 2f 6a f2 1c 61 13 05 07 11 04 6a 16 6f } //01 00 
		$a_80_1 = {53 74 61 6e 47 72 61 62 62 65 72 2e 65 78 65 } //StanGrabber.exe  01 00 
		$a_80_2 = {44 69 73 63 6f 72 64 43 61 6e 61 72 79 } //DiscordCanary  00 00 
	condition:
		any of ($a_*)
 
}