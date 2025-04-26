
rule VirTool_Win32_CeeInject_RX_bit{
	meta:
		description = "VirTool:Win32/CeeInject.RX!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {a1 18 7c 47 00 03 03 8a 10 [0-10] 89 c0 [0-10] 80 f2 94 a1 ?? ?? ?? ?? 03 03 88 10 [0-10] 89 c0 [0-10] ff 03 81 3b } //1
		$a_03_1 = {31 f6 89 db 89 d2 68 e0 52 00 00 5f 01 f8 a1 ?? ?? ?? ?? 01 f8 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}