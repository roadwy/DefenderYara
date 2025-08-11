
rule Trojan_Win32_Zusy_BAA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 c5 89 45 fc 53 56 57 } //1
		$a_01_1 = {89 45 e0 64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 8b 00 8b 40 18 } //2
		$a_03_2 = {ff d0 85 c0 0f 84 ?? ?? ?? ?? 83 f8 57 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1) >=2
 
}