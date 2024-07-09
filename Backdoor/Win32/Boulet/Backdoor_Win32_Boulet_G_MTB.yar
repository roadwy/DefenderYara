
rule Backdoor_Win32_Boulet_G_MTB{
	meta:
		description = "Backdoor:Win32/Boulet.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8b c6 f7 f1 46 8a 92 ?? ?? ?? ?? 30 96 ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}