
rule Trojan_Win32_Azorult_NC_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {51 50 50 50 50 ff 15 90 02 04 46 3b f3 90 18 e8 90 02 04 30 90 02 02 83 90 02 02 75 90 02 03 50 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}