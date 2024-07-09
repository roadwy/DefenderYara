
rule Trojan_Win32_RedLine_RDAU_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {4f 81 cf 00 ff ff ff 47 8a 44 3d 10 88 44 35 10 88 4c 3d 10 0f b6 44 35 10 03 c2 0f b6 c0 8a 44 05 10 30 83 ?? ?? ?? ?? 43 81 fb 00 b2 02 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}