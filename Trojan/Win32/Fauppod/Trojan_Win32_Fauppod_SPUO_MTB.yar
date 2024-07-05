
rule Trojan_Win32_Fauppod_SPUO_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.SPUO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_81_0 = {49 68 7a 70 68 65 75 6c 64 53 } //02 00  IhzpheuldS
		$a_01_1 = {49 68 7a 70 68 65 75 6c 64 53 } //00 00  IhzpheuldS
	condition:
		any of ($a_*)
 
}