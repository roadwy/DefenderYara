
rule Trojan_Win32_GuLoader_SIBM14_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBM14!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0c 03 0f 90 08 70 01 80 f1 00 [0-aa] 81 f1 ?? ?? ?? ?? 90 08 60 02 89 0c 03 90 08 c0 01 83 c0 04 90 08 aa 01 3d ?? ?? ?? ?? [0-60] 0f 85 ?? ?? ?? ?? 90 08 ba 01 ff d3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}