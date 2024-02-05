
rule Trojan_Win32_Lokibot_SS_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 c9 31 d2 6a 01 5e 81 c6 f7 72 00 00 87 d6 80 34 01 d6 41 89 d3 39 d9 75 f5 } //01 00 
		$a_01_1 = {80 34 01 d6 41 89 d3 39 d9 75 f5 } //00 00 
	condition:
		any of ($a_*)
 
}