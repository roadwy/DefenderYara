
rule Backdoor_Win32_Zegost_GNX_MTB{
	meta:
		description = "Backdoor:Win32/Zegost.GNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 55 f0 8b 45 08 03 45 f8 8a 0a 32 08 8b 55 0c 03 55 f0 88 0a } //5
		$a_01_1 = {8b ec 83 ec 0c c6 45 f4 44 c6 45 f5 6c c6 45 f6 6c c6 45 f7 53 c6 45 f8 68 c6 45 f9 65 c6 45 fa 6c c6 45 fb 6c c6 45 fc 00 8b 45 08 50 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}