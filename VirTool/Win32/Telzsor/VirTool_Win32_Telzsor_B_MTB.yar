
rule VirTool_Win32_Telzsor_B_MTB{
	meta:
		description = "VirTool:Win32/Telzsor.B!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 c8 83 c0 10 8b 4d f8 89 41 20 eb 46 } //1
		$a_01_1 = {8b 4d ac 51 68 00 10 02 00 8b 55 ac 52 68 04 20 00 80 8b 45 d0 50 ff } //1
		$a_01_2 = {83 c4 04 8b 4d a4 89 8d 0c fc ff ff 89 85 04 fc ff ff 89 95 08 fc ff ff 8b 95 0c fc ff ff 8b 82 18 02 00 00 3b 85 04 fc ff ff 75 38 } //1
		$a_01_3 = {c7 45 c4 00 00 00 00 c7 45 b8 00 00 00 00 8b f4 68 00 10 02 00 6a 08 8b fc ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}