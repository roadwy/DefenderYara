
rule Trojan_Win32_Qbot_MT_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec a1 90 02 04 a3 90 02 04 90 18 55 8b ec 57 90 02 04 a1 90 02 04 a3 90 02 04 8b 90 02 05 8b 90 02 04 89 90 02 05 a1 90 02 04 2d 90 02 04 a3 90 00 } //01 00 
		$a_02_1 = {8b ff c7 05 90 02 08 01 05 90 02 06 8b 0d 90 02 04 8b 15 90 02 04 89 11 33 c0 e9 90 09 05 00 a1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}