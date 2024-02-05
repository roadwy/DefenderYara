
rule Trojan_Win32_Stealer_CP_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 10 30 04 31 81 bc 24 20 0c 00 00 91 05 00 00 75 56 } //02 00 
		$a_03_1 = {81 fe ce 0d 26 09 0f 8f 90 02 04 46 81 fe 9c b3 61 36 7c af 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}