
rule Trojan_Win32_StealC_VNM_MTB{
	meta:
		description = "Trojan:Win32/StealC.VNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 04 1e 83 ff 0f 75 } //1
		$a_03_1 = {b8 31 a2 00 00 01 44 24 ?? 8b 44 24 ?? 8a 0c 30 8b 15 ?? ?? ?? ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ab 05 00 00 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}