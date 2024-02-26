
rule Trojan_Win32_Khalesi_GMA_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.GMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {29 fb 47 31 31 52 5b 81 c1 04 00 00 00 39 c1 } //0a 00 
		$a_01_1 = {31 16 81 c6 04 00 00 00 4b 57 59 39 c6 } //00 00 
	condition:
		any of ($a_*)
 
}