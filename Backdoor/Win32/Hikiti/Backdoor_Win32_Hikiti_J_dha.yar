
rule Backdoor_Win32_Hikiti_J_dha{
	meta:
		description = "Backdoor:Win32/Hikiti.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 75 f6 85 90 09 12 00 8d 14 85 00 00 00 00 2b 90 01 01 8b 90 01 01 31 90 01 01 83 90 01 01 04 83 90 09 19 00 8d 90 01 01 fb c1 90 01 01 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}