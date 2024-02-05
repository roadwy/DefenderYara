
rule Trojan_Win32_Agent_AIA{
	meta:
		description = "Trojan:Win32/Agent.AIA,SIGNATURE_TYPE_PEHSTR,6e 00 64 00 03 00 00 64 00 "
		
	strings :
		$a_01_0 = {b8 46 55 43 4b 3d 46 55 43 4b 75 } //0a 00 
		$a_01_1 = {46 55 43 4b 3d 46 55 43 4b } //0a 00 
		$a_01_2 = {66 75 63 6b 61 6c 6c 62 6c 79 61 } //00 00 
	condition:
		any of ($a_*)
 
}