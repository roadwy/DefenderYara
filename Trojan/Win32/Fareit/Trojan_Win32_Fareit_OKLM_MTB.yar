
rule Trojan_Win32_Fareit_OKLM_MTB{
	meta:
		description = "Trojan:Win32/Fareit.OKLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {14 11 40 00 fc 35 40 00 08 36 40 00 0c 36 40 00 10 } //01 00 
		$a_01_1 = {31 00 00 8b c0 90 90 8b 15 50 fc 48 00 88 02 90 } //00 00 
	condition:
		any of ($a_*)
 
}