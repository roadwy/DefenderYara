
rule Backdoor_Win32_Rbot_gen_I{
	meta:
		description = "Backdoor:Win32/Rbot.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 8d f8 fb ff ff 8b 85 fc fd ff ff 6b c0 3c ff b0 90 01 03 00 8b 85 fc fd ff ff 6b c0 3c 05 90 01 03 00 50 68 90 01 03 00 8d 85 00 fe ff ff 50 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}