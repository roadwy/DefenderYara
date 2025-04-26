
rule Backdoor_Win32_Pigeon_GMX_MTB{
	meta:
		description = "Backdoor:Win32/Pigeon.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {18 2a 40 00 00 63 40 00 d8 29 40 00 40 2a 40 00 04 63 40 00 d8 29 40 00 58 2a 40 00 08 63 40 00 d8 29 40 00 } //10
		$a_01_1 = {35 36 71 2e 35 64 36 64 2e 63 6f 6d } //1 56q.5d6d.com
		$a_80_2 = {5c 64 6e 66 61 68 6b 2e 61 68 6b } //\dnfahk.ahk  1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}