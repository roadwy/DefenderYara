
rule Trojan_Win32_Phorpiex_APH_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.APH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 18 31 40 00 8d 8d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 83 c4 08 eb 15 68 60 31 40 00 8d 95 } //3
		$a_03_1 = {6a 00 6a 00 6a 00 6a 00 68 a8 31 40 00 ff 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 bd ?? ?? ?? ?? ?? 74 34 6a 00 6a 00 6a 00 6a 00 8d 85 } //2
		$a_01_2 = {39 00 31 00 2e 00 32 00 30 00 32 00 2e 00 32 00 33 00 33 00 2e 00 31 00 34 00 31 00 } //4 91.202.233.141
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*4) >=9
 
}