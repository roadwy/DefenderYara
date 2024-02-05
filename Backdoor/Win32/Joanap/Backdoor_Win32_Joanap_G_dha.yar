
rule Backdoor_Win32_Joanap_G_dha{
	meta:
		description = "Backdoor:Win32/Joanap.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {52 70 63 73 73 00 90 02 0a 25 73 5c 25 73 90 02 0a 77 61 75 73 65 72 76 2e 64 6c 6c 00 64 2e 62 61 74 90 00 } //00 00 
		$a_00_1 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}