
rule Trojan_Win32_Ursnif_D_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c3 8b ff c7 05 [0-30] 01 05 [0-20] 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 } //1
		$a_02_1 = {03 4d fc 89 0d ?? ?? ?? ?? 8b 55 ?? 89 55 ?? 8b 45 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}