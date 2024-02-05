
rule Trojan_Win32_Qbot_AE_MTB{
	meta:
		description = "Trojan:Win32/Qbot.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 52 6b 64 65 5f 69 6e 74 65 72 6e 61 6c 5f 4b 43 6f 6e 66 69 67 47 72 6f 75 70 47 75 69 00 } //01 00 
		$a_01_1 = {00 57 69 6e 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}