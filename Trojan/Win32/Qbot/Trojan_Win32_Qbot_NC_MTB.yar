
rule Trojan_Win32_Qbot_NC_MTB{
	meta:
		description = "Trojan:Win32/Qbot.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {80 c3 3d 02 db 81 [0-05] 2a da 89 [0-05] 02 [0-05] 89 [0-06] 83 c5 04 81 [0-07] 8b [0-05] 8b [0-05] 8b [0-05] 8b [0-05] 90 18 a1 [0-04] 2b c7 3d [0-04] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}