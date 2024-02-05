
rule Backdoor_Win32_Otlard_A{
	meta:
		description = "Backdoor:Win32/Otlard.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 f8 67 c6 45 f9 6f c6 45 fa 6f c6 45 fb 74 c6 45 fc 6b } //00 00 
	condition:
		any of ($a_*)
 
}