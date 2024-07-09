
rule Trojan_Win32_Redline_GBO_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {a1 60 7b 58 00 80 34 38 8e 81 3d ?? ?? ?? ?? 1b 0e 00 00 8b 1d ?? ?? ?? ?? 75 ?? 8d 84 24 ?? ?? ?? ?? 50 56 } //10
		$a_80_1 = {47 4f 44 45 43 49 4b 4f 4a 49 } //GODECIKOJI  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}