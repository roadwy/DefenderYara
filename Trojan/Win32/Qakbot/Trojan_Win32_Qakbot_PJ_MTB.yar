
rule Trojan_Win32_Qakbot_PJ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_1 = {32 33 39 38 30 63 39 30 33 35 65 61 62 32 64 62 64 65 61 35 31 65 38 61 33 38 33 65 32 32 65 64 39 62 35 31 64 35 61 63 32 37 31 32 64 38 38 62 } //01 00 
		$a_01_2 = {33 33 65 61 36 39 33 38 38 64 34 64 33 36 34 36 66 35 30 31 61 62 38 31 66 38 38 37 31 63 36 36 38 39 61 63 32 33 35 66 35 34 37 62 35 34 33 33 } //00 00 
	condition:
		any of ($a_*)
 
}