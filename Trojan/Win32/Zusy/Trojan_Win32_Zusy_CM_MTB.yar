
rule Trojan_Win32_Zusy_CM_MTB{
	meta:
		description = "Trojan:Win32/Zusy.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {59 69 74 69 73 61 67 69 61 73 65 67 61 69 73 64 6f 6b 78 } //02 00 
		$a_01_1 = {6f 69 6f 61 69 64 66 6a 61 6f 65 69 67 68 61 75 65 68 67 } //02 00 
		$a_01_2 = {46 67 69 73 6f 65 67 69 6f 61 65 67 6a 61 64 66 } //02 00 
		$a_01_3 = {46 6f 69 61 64 73 6f 76 63 69 6a 61 73 67 66 69 61 67 } //00 00 
	condition:
		any of ($a_*)
 
}