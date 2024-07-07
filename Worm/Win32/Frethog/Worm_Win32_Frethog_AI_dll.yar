
rule Worm_Win32_Frethog_AI_dll{
	meta:
		description = "Worm:Win32/Frethog.AI!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 50 44 41 54 45 44 41 54 41 3a } //1 UPDATEDATA:
		$a_01_1 = {44 4f 57 4e 4c 4f 41 44 3a } //1 DOWNLOAD:
		$a_01_2 = {56 45 52 53 4f 4e 3a 41 6e 74 2d 56 } //2 VERSON:Ant-V
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}