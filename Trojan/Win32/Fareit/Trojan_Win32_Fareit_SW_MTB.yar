
rule Trojan_Win32_Fareit_SW_MTB{
	meta:
		description = "Trojan:Win32/Fareit.SW!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 08 80 f1 82 8b 5d fc 03 da 73 05 e8 2b c0 f9 ff 88 0b 42 40 81 fa dd 5f 00 00 75 } //00 00 
	condition:
		any of ($a_*)
 
}