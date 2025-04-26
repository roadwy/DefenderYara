
rule Trojan_Win32_Zbot_SP_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 73 65 6e 64 43 6d 64 25 64 } //1 Global\sendCmd%d
		$a_01_1 = {43 6f 6f 6b 69 65 3a 20 42 41 49 44 55 49 44 3d 34 35 35 31 42 33 41 38 37 33 33 31 30 41 31 44 39 46 31 44 38 46 33 38 34 37 46 41 44 41 35 32 3a 46 47 3d } //1 Cookie: BAIDUID=4551B3A873310A1D9F1D8F3847FADA52:FG=
		$a_01_2 = {48 6d 5f 6c 76 74 5f 39 66 31 34 61 61 61 30 33 38 62 62 62 61 38 62 31 32 65 63 32 61 34 61 33 65 35 31 64 32 35 34 3d 31 33 38 31 39 32 36 34 34 38 } //1 Hm_lvt_9f14aaa038bbba8b12ec2a4a3e51d254=1381926448
		$a_01_3 = {47 6c 6f 62 61 6c 5c 72 65 63 76 43 6d 64 5f 25 64 } //1 Global\recvCmd_%d
		$a_01_4 = {68 69 2e 62 61 69 64 75 2e 63 6f 6d } //1 hi.baidu.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}