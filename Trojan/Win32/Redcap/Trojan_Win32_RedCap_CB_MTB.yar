
rule Trojan_Win32_RedCap_CB_MTB{
	meta:
		description = "Trojan:Win32/RedCap.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {0f b6 14 03 30 14 2f 83 c7 01 3b 7c 24 1c 72 a3 } //03 00 
		$a_01_1 = {43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 44 65 73 6b 74 6f 70 5c 52 65 73 6f 75 72 63 65 4c 6f 63 61 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}