
rule Backdoor_Win32_BazarLoaderCrypt_SN_MTB{
	meta:
		description = "Backdoor:Win32/BazarLoaderCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 40 81 cb 00 10 00 00 53 52 6a 00 ff 15 ?? ?? ?? ?? 8b e8 e8 ?? ?? ?? ?? 8b f0 } //4
		$a_03_1 = {50 55 51 53 6a 01 53 52 ff 15 ?? ?? ?? ?? 5f 85 c0 5b 0f 95 c0 5d 83 c4 0c c3 } //4
		$a_01_2 = {46 75 63 6b 20 44 65 66 } //2 Fuck Def
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_01_2  & 1)*2) >=10
 
}