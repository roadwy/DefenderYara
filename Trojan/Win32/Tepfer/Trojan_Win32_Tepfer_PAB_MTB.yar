
rule Trojan_Win32_Tepfer_PAB_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 4c 24 20 89 4c 24 10 8d 0c 07 c1 e8 05 89 44 24 14 8b 44 24 24 01 44 24 14 8b 44 24 10 33 c1 31 44 24 14 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 10 89 1d cc 22 7f 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}