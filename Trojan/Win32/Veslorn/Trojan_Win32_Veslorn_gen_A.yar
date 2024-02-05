
rule Trojan_Win32_Veslorn_gen_A{
	meta:
		description = "Trojan:Win32/Veslorn.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {c6 44 24 31 02 66 89 7c 24 36 88 4c 24 54 88 44 24 55 bd 90 01 04 eb 02 33 ff ff d3 99 b9 fa 00 00 00 90 00 } //01 00 
		$a_02_1 = {8d 4c 24 14 6a 10 51 6a 00 52 68 90 01 02 00 10 57 ff 90 01 01 4e 75 90 01 01 83 3d 90 01 02 00 10 01 75 90 01 01 5d 5b 6a 00 ff 15 90 00 } //01 00 
		$a_02_2 = {8d 4c 24 14 6a 10 51 6a 00 52 68 90 01 02 00 10 57 ff d5 4e 75 e1 83 3d 90 01 02 00 10 01 75 cb 6a 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}