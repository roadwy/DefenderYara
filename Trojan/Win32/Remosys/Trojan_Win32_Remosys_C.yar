
rule Trojan_Win32_Remosys_C{
	meta:
		description = "Trojan:Win32/Remosys.C,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 6c 65 78 6a 75 73 74 6f 5c 44 65 73 6b 74 6f 70 5c 65 78 69 74 5c 52 65 6c 65 61 73 65 5c 65 78 69 74 2e 70 64 62 } //01 00 
		$a_01_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 20 00 69 00 2e 00 63 00 6d 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}