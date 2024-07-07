
rule TrojanDropper_Win32_Agent_KM{
	meta:
		description = "TrojanDropper:Win32/Agent.KM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2d 90 01 04 2d 3d 30 0d 0a 73 65 74 20 2d 90 01 04 2d 3d 31 0d 0a 73 65 74 20 2d 90 01 04 2d 3d 32 0d 0a 73 65 74 20 2d 90 01 04 2d 3d 33 0d 0a 73 65 74 20 2d 90 01 04 2d 3d 34 0d 0a 90 00 } //1
		$a_01_1 = {2d 25 20 24 24 24 24 20 24 24 24 24 24 20 24 24 24 24 24 20 24 20 20 20 24 20 24 24 24 24 24 20 20 3e 3e } //1 -% $$$$ $$$$$ $$$$$ $   $ $$$$$  >>
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}