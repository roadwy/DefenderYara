
rule Trojan_Win32_Azorult_RK_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 c0 70 00 00 00 03 45 ?? 0f b7 40 ?? 89 45 ?? 8b 45 ?? 89 45 ?? 8b 4d ?? 33 4d ?? 89 4d ?? 8b 4d ?? 03 4d ?? 89 4d ?? e9 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? b9 0e 00 00 00 8d 55 ?? 83 ec 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}