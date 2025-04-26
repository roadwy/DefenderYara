
rule Backdoor_Win32_Oderoor_gen_H{
	meta:
		description = "Backdoor:Win32/Oderoor.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 01 00 00 00 f0 0f c1 01 40 83 3d ?? ?? ?? 00 00 75 08 8d 85 00 ff ff ff eb 06 } //1
		$a_03_1 = {8a 85 00 ff ff ff 0a c0 74 09 83 3d ?? ?? ?? 00 00 76 e6 } //1
		$a_01_2 = {8d 45 ac 50 8d 45 bc 50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}