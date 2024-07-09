
rule Trojan_Win32_Redline_GH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 f0 0f b6 0c 37 c1 e8 02 0f be 98 ?? ?? ?? ?? 6b db 4c b8 ?? ?? ?? ?? f7 eb c1 fb 1f 89 d0 ba ?? ?? ?? ?? c1 f8 04 29 d8 0f af c2 31 c1 88 0c 37 83 c6 01 83 fe 10 75 c7 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}