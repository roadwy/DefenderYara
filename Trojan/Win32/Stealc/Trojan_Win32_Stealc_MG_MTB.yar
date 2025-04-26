
rule Trojan_Win32_Stealc_MG_MTB{
	meta:
		description = "Trojan:Win32/Stealc.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 31 a2 00 00 01 85 b0 da ff ff a1 ?? ?? ?? ?? 03 85 b4 da ff ff 8b 8d b0 da ff ff 03 8d b4 da ff ff 8a 09 88 08 81 3d ?? ?? ?? ?? ab 05 00 00 75 19 } //2
		$a_03_1 = {30 04 39 83 fb 0f 75 1e 90 0a 0f 00 8b 8d } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}