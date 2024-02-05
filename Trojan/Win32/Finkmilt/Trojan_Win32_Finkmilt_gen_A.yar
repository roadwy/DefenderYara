
rule Trojan_Win32_Finkmilt_gen_A{
	meta:
		description = "Trojan:Win32/Finkmilt.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 4d 08 ff 75 08 e8 90 01 01 ff ff ff 90 00 } //01 00 
		$a_01_1 = {6c 64 72 2e 64 6c 6c 2c 49 6e 66 69 6c 74 72 61 74 65 } //01 00 
		$a_01_2 = {73 67 6f 70 65 2e 73 79 73 } //00 00 
	condition:
		any of ($a_*)
 
}