
rule Backdoor_Win32_Hupigon_FF{
	meta:
		description = "Backdoor:Win32/Hupigon.FF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {f7 d8 1b c0 25 ba d8 ff ff 05 46 27 00 00 c2 90 01 01 00 90 00 } //02 00 
		$a_02_1 = {3d 05 10 00 00 77 90 01 01 74 90 01 01 2d 01 10 00 00 74 90 01 01 83 e8 03 0f 85 90 01 02 ff ff 90 00 } //01 00 
		$a_00_2 = {c9 cf cf df d6 f7 bb fa } //00 00 
	condition:
		any of ($a_*)
 
}