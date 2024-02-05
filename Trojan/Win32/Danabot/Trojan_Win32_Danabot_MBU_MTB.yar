
rule Trojan_Win32_Danabot_MBU_MTB{
	meta:
		description = "Trojan:Win32/Danabot.MBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6c 76 72 2e 64 6c 6c 00 54 79 59 69 } //00 00 
	condition:
		any of ($a_*)
 
}