
rule Trojan_Win32_Stealc_MH_MTB{
	meta:
		description = "Trojan:Win32/Stealc.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 31 a2 00 00 01 85 a0 da ff ff a1 90 01 04 03 85 a4 da ff ff 8b 8d a0 da ff ff 03 8d a4 da ff ff 8a 09 88 08 81 3d 90 01 04 ab 05 00 00 90 00 } //2
		$a_01_1 = {30 04 33 83 ff 0f 75 12 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}