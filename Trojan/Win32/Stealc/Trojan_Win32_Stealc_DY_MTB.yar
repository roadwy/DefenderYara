
rule Trojan_Win32_Stealc_DY_MTB{
	meta:
		description = "Trojan:Win32/Stealc.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 44 0c 0c 34 ?? 0f b6 c0 66 89 84 4c ?? ?? ?? ?? 41 3b ce 7c } //1
		$a_03_1 = {8a 44 0c 1c 04 ?? 88 84 0c ?? ?? ?? ?? 41 3b ca 7c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}