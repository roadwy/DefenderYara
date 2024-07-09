
rule Trojan_Win32_Upatre_DSK_MTB{
	meta:
		description = "Trojan:Win32/Upatre.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 d0 0f b6 80 ?? ?? ?? ?? 0f b6 55 ?? 31 c2 8b 45 ?? 05 ?? ?? ?? ?? 88 10 83 45 ?? 01 a1 ?? ?? ?? ?? 39 45 ?? 7c } //2
		$a_02_1 = {89 d0 0f b6 80 ?? ?? ?? ?? 89 c1 8b 55 f4 8b 45 08 01 d0 0f b6 55 e7 31 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 0c 7c } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}