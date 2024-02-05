
rule Trojan_Win32_Qbot_AD_MTB{
	meta:
		description = "Trojan:Win32/Qbot.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b ca 01 48 90 01 01 8b 48 90 01 01 81 e9 90 01 04 31 48 90 01 01 8b 50 90 01 01 2b 50 90 01 01 33 50 90 01 01 81 f2 90 01 04 89 50 90 01 01 8b 48 90 01 01 33 88 90 01 04 83 f1 90 01 01 29 88 90 01 04 8b 48 90 01 01 03 48 90 01 01 31 88 90 01 04 81 ff 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}