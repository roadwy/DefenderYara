
rule Backdoor_Win32_Escad_O_dha{
	meta:
		description = "Backdoor:Win32/Escad.O!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 14 08 80 c2 ?? 80 f2 ?? 88 14 08 40 3b c6 7c ef } //2
		$a_01_1 = {b8 2d 2d 2d 2d 8d } //1
		$a_00_2 = {3d 3d 3d 20 25 30 34 64 2e 25 30 32 64 2e 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 20 3d 3d 3d } //1 === %04d.%02d.%02d %02d:%02d:%02d ===
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Backdoor_Win32_Escad_O_dha_2{
	meta:
		description = "Backdoor:Win32/Escad.O!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 14 08 80 c2 ?? 80 f2 ?? 88 14 08 40 3b c6 7c ef } //2
		$a_01_1 = {b8 2d 2d 2d 2d 8d } //1
		$a_00_2 = {3d 3d 3d 20 25 30 34 64 2e 25 30 32 64 2e 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 20 3d 3d 3d } //1 === %04d.%02d.%02d %02d:%02d:%02d ===
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}