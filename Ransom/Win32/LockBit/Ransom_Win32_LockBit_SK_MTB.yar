
rule Ransom_Win32_LockBit_SK_MTB{
	meta:
		description = "Ransom:Win32/LockBit.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {66 33 c3 c7 45 ?? ?? ?? ?? ?? 66 89 45 ?? 0f b7 05 ?? ?? ?? ?? 66 33 c3 c7 45 ?? ?? ?? ?? ?? 66 89 45 ?? 0f b7 05 ?? ?? ?? ?? 66 33 c3 c7 45 ?? ?? ?? ?? ?? 66 89 45 ?? 0f b7 05 ?? ?? ?? ?? 66 33 c3 c7 45 ?? ?? ?? ?? ?? 66 89 45 ?? 0f b7 05 } //2
		$a_02_1 = {85 c0 74 0a 8d 8c 24 ?? ?? ?? ?? 51 ff d0 8d 84 24 ?? ?? ?? ?? c7 84 24 ?? ?? ?? ?? 3c 00 00 00 89 84 24 ?? ?? ?? ?? 8d 44 24 ?? 89 84 24 ?? ?? ?? ?? 8b 44 24 ?? 89 84 24 ?? ?? ?? ?? 8d 84 24 ?? ?? ?? ?? 50 c7 84 24 ?? ?? ?? ?? 00 00 00 00 c7 84 24 ?? ?? ?? ?? 00 00 00 00 c7 84 24 ?? ?? ?? ?? 00 00 00 00 c7 84 24 ?? ?? ?? ?? 00 00 00 00 c7 84 24 ?? ?? ?? ?? 00 00 00 00 ff 15 ?? ?? ?? ?? 68 e8 03 00 00 ff 15 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}