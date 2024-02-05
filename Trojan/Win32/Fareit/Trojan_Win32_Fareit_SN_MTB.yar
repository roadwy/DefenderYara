
rule Trojan_Win32_Fareit_SN_MTB{
	meta:
		description = "Trojan:Win32/Fareit.SN!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8d 1c 01 30 13 41 81 f9 6f 5a 00 00 75 } //00 00 
	condition:
		any of ($a_*)
 
}