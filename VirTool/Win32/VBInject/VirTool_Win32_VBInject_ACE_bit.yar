
rule VirTool_Win32_VBInject_ACE_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 55 8b ec 83 5b 39 18 75 ?? 81 78 04 ec 0c 56 8d 75 ?? 31 db 53 53 53 54 ff 75 36 52 51 54 ff d0 } //1
		$a_01_1 = {0f 31 31 f0 4b 0f c8 e2 f7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}