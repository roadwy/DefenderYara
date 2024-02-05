
rule Trojan_Win32_Qbot_NC_MTB{
	meta:
		description = "Trojan:Win32/Qbot.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {80 c3 3d 02 db 81 90 02 05 2a da 89 90 02 05 02 90 02 05 89 90 02 06 83 c5 04 81 90 02 07 8b 90 02 05 8b 90 02 05 8b 90 02 05 8b 90 02 05 90 18 a1 90 02 04 2b c7 3d 90 02 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}