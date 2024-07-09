
rule Trojan_Win32_Smokeloader_HNC_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.HNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 5f 33 cd 33 c0 5e 90 09 06 00 ff 15 } //5
		$a_01_1 = {8d 95 ec fb ff ff 52 50 50 66 89 85 ec fb ff ff 89 85 ee fb ff ff 89 85 f2 fb ff ff 89 85 f6 fb ff ff 66 89 85 fa fb ff ff } //5
		$a_03_2 = {55 8b ec 81 ec ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 c5 89 45 fc 56 57 } //5
		$a_03_3 = {25 73 20 25 63 00 00 [0-09] 6d 73 69 6d 67 33 32 2e 64 6c 6c 00 } //1
		$a_03_4 = {25 73 20 25 63 00 [0-09] 6d 00 73 00 69 00 6d 00 67 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1
		$a_01_5 = {b8 31 a2 00 00 01 44 24 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_03_2  & 1)*5+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=16
 
}