
rule VirTool_Win32_CeeInject_BDN_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDN!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f0 8d 45 fc 50 6a 40 68 0d 58 00 00 56 e8 90 01 03 ff 33 c0 33 db 90 02 10 89 5d f8 90 02 10 8a 90 02 10 80 f2 9b 90 01 01 ce 03 4d f8 88 11 40 40 90 00 } //01 00 
		$a_03_1 = {89 75 fc ff 55 fc 90 0a 30 00 43 81 fb 0d 58 00 00 75 dd 90 02 10 81 c6 44 1c 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}