
rule Trojan_Win32_Azorult_RD_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 ff 3b de 7e ?? 8b 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 39 83 fb 19 75 } //1
		$a_02_1 = {33 c5 89 45 ?? 8b 45 ?? 56 33 f6 57 89 85 ?? ?? ?? ?? 81 fb 2e 0f 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}