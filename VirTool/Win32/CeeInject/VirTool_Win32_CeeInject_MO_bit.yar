
rule VirTool_Win32_CeeInject_MO_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MO!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {a1 60 40 41 00 03 45 d8 8b 4d f0 8b 95 48 fe ff ff 8a 0c 8a 88 08 } //01 00 
		$a_01_1 = {8d 44 0a 0a 89 45 ec 8b 0d 60 40 41 00 03 4d d8 0f be 11 03 95 9c fd ff ff a1 60 40 41 00 03 45 d8 88 10 } //00 00 
	condition:
		any of ($a_*)
 
}