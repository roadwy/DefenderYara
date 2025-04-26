
rule Trojan_Win32_Zusy_ASFO_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ASFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 6a 40 68 00 30 00 00 68 a0 07 00 00 6a 00 56 ff 15 ?? ?? ?? ?? 8b f8 85 ff } //2
		$a_03_1 = {83 c4 0c 8d 85 f0 fd ff ff 50 8d 85 f4 fd ff ff 50 ff 15 ?? ?? ?? ?? 8d 85 f4 fd ff ff 50 6a 00 6a 00 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}