
rule Trojan_Win32_Azorult_AD_MTB{
	meta:
		description = "Trojan:Win32/Azorult.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {46 85 ff 31 c9 3d ?? ?? ?? ?? 0b 0f 66 81 fb ?? ?? e8 ?? ?? ?? ?? e9 ?? ?? 00 00 [0-a0] 81 fa ?? ?? ?? ?? 39 c1 0f } //1
		$a_03_1 = {56 66 81 ff ?? ?? 33 0c 24 85 db 5e 66 81 fb ?? ?? c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Azorult_AD_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.AD!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c9 89 4c 24 14 8d 64 24 00 81 f9 0d 04 00 00 75 0a } //5
		$a_01_1 = {33 c9 33 c0 8d 54 24 18 52 66 89 44 24 14 66 89 4c 24 16 8b 44 24 14 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}