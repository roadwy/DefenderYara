
rule Trojan_Win32_Azorult_SM_MTB{
	meta:
		description = "Trojan:Win32/Azorult.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 45 70 ff 8d a4 fd ff ff ?? ?? ?? ?? ?? ?? 8b 45 6c 89 5f 04 89 07 } //1
		$a_03_1 = {33 45 74 89 35 ?? ?? ?? 00 89 85 a8 fd ff ff 8b 85 a8 fd ff ff 29 45 6c 81 3d ?? ?? ?? 00 b6 0c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}