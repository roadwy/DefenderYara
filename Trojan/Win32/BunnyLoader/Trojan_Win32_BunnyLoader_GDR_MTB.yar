
rule Trojan_Win32_BunnyLoader_GDR_MTB{
	meta:
		description = "Trojan:Win32/BunnyLoader.GDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 01 88 04 37 8b c6 88 11 8d 75 ed 0f b6 04 07 03 45 ac 0f b6 c0 0f b6 0c 38 0f be c6 33 c8 } //00 00 
	condition:
		any of ($a_*)
 
}