
rule VirTool_Win32_Ceeinject_NE_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.NE!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b cb 33 f6 66 d1 e8 66 d1 e0 8b 35 c0 61 42 00 97 8b fe ff d7 33 c0 } //2
		$a_03_1 = {eb d4 8b 85 90 01 04 0f af 85 90 01 04 8b 8d 90 01 04 2b 8d 90 01 04 03 c1 0f be 55 f3 03 d0 88 55 f3 90 00 } //2
		$a_01_2 = {6d 61 6c 77 61 72 65 67 65 6e 20 66 72 6f 6d 20 61 76 61 73 74 } //1 malwaregen from avast
		$a_01_3 = {6d 61 72 6b 65 74 73 20 73 73 73 61 73 73 73 3a } //1 markets sssasss:
		$a_01_4 = {6b 6f 6c 6c 6c 20 73 64 20 73 20 76 76 66 66 64 3a } //1 kolll sd s vvffd:
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}