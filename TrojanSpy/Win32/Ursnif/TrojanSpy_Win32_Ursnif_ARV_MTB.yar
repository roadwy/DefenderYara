
rule TrojanSpy_Win32_Ursnif_ARV_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.ARV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 6c 24 10 81 c3 7c 3e 3d 01 89 9c 2f 1c d9 ff ff 0f b7 3d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 8d 44 08 fd 3b f9 77 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}