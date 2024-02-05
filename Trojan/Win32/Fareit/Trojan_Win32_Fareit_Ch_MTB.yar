
rule Trojan_Win32_Fareit_Ch_MTB{
	meta:
		description = "Trojan:Win32/Fareit.Ch!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 58 06 4b 85 db 7c 54 43 c7 06 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}