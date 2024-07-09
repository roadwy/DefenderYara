
rule Backdoor_Win32_Hikiti_J_dha{
	meta:
		description = "Backdoor:Win32/Hikiti.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 75 f6 85 90 09 12 00 8d 14 85 00 00 00 00 2b ?? 8b ?? 31 ?? 83 ?? 04 83 90 09 19 00 8d ?? fb c1 ?? 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}