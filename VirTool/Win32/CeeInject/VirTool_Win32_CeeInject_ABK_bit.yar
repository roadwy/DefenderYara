
rule VirTool_Win32_CeeInject_ABK_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 52 50 8b 06 99 03 04 24 13 54 24 90 01 01 83 c4 08 8b d1 8a 12 80 f2 90 01 01 88 10 ff 06 41 81 3e 90 01 04 75 90 00 } //1
		$a_03_1 = {31 c9 83 c1 5f 31 db 03 5d 90 01 01 87 cb 01 cb 87 d9 ff d1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}