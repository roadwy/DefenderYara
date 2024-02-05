
rule Trojan_Win32_Stealer_CL_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 75 08 81 f6 39 16 a9 28 83 c6 7e 2b f0 33 75 08 89 75 08 6a 00 ff 15 90 01 04 89 45 08 81 f8 01 03 09 80 0f 85 90 00 } //01 00 
		$a_00_1 = {89 45 10 ba 28 00 00 00 03 15 08 0c 61 00 81 ea 99 fd ac 9b 33 15 0d 0c 61 00 81 c2 c6 29 bd 93 2b 15 0d 0c 61 00 89 55 0c } //00 00 
	condition:
		any of ($a_*)
 
}