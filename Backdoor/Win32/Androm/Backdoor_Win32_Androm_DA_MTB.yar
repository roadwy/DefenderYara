
rule Backdoor_Win32_Androm_DA_MTB{
	meta:
		description = "Backdoor:Win32/Androm.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 08 8b 4d 0c 0f b6 11 33 c2 88 45 08 8b 45 0c 83 c0 01 89 45 0c 8b 4d 10 83 e9 01 89 4d 10 eb d7 } //2
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //2 VirtualAlloc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}