
rule VirTool_Win32_Injector_HI{
	meta:
		description = "VirTool:Win32/Injector.HI,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 6a 01 6a ff 6a 20 ff 15 } //1
		$a_01_1 = {3c 14 52 73 45 b3 52 73 36 b1 51 73 f7 71 4f 73 5e 47 44 73 68 91 44 73 ea } //1
		$a_01_2 = {8b d0 8d 8d 0c fd ff ff ff d6 50 ff d7 8b d0 8d 8d 08 fd ff ff ff d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}