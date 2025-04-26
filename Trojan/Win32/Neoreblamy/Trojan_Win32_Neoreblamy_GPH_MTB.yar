
rule Trojan_Win32_Neoreblamy_GPH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 4d f4 88 41 01 0f b6 45 ff 03 45 f4 89 45 f4 eb 92 } //3
		$a_01_1 = {99 6a 0f 59 f7 f9 83 c2 0a 88 55 ff 0f b6 45 ff 03 45 f4 3b 45 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}