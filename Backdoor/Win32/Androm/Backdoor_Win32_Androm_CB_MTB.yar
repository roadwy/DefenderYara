
rule Backdoor_Win32_Androm_CB_MTB{
	meta:
		description = "Backdoor:Win32/Androm.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {4f 11 f6 30 ca 50 08 60 90 01 01 61 75 e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}