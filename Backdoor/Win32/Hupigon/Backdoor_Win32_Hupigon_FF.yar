
rule Backdoor_Win32_Hupigon_FF{
	meta:
		description = "Backdoor:Win32/Hupigon.FF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {f7 d8 1b c0 25 ba d8 ff ff 05 46 27 00 00 c2 ?? 00 } //1
		$a_02_1 = {3d 05 10 00 00 77 ?? 74 ?? 2d 01 10 00 00 74 ?? 83 e8 03 0f 85 ?? ?? ff ff } //2
		$a_00_2 = {c9 cf cf df d6 f7 bb fa } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1) >=3
 
}