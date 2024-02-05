
rule Trojan_Win32_Lokibot_Inj_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.Inj!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {e0 fd e6 e0 6c ee 43 fd e6 e0 fd 6c ee 47 e6 e0 fd e6 6c ee } //00 00 
	condition:
		any of ($a_*)
 
}