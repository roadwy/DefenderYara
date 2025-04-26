
rule VirTool_Win32_CeeInject_ANG_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ANG!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 8d 8f fc ff ff 33 8d 88 fc ff ff 88 8d 87 fc ff ff 8b 95 ec fd ff ff 03 55 10 8b 85 94 fc ff ff 2b 85 ec fd ff ff 03 95 cc fc ff ff 8d 8c 82 b9 00 00 00 89 8d cc fc ff ff 8b 95 cc fc ff ff 83 c2 08 39 95 ec fd ff ff 75 17 8b 85 88 fc ff ff 2b 45 10 8b 8d cc fc ff ff 2b c8 89 8d cc fc ff ff 8b 95 ac fc ff ff 03 15 40 91 45 00 03 15 4c 91 45 00 03 15 40 91 45 00 89 15 40 91 45 00 8a 85 87 fc ff ff 88 85 90 fc ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}