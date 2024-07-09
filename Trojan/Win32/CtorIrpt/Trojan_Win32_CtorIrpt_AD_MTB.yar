
rule Trojan_Win32_CtorIrpt_AD_MTB{
	meta:
		description = "Trojan:Win32/CtorIrpt.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {fc ff ff 56 c6 85 ?? fc ff ff 69 c6 85 ?? fc ff ff 72 c6 85 ?? fc ff ff 74 c6 85 ?? fc ff ff 75 c6 85 ?? fc ff ff 61 c6 85 ?? fc ff ff 6c c6 85 ?? fc ff ff 41 c6 85 ?? fc ff ff 6c c6 85 ?? fc ff ff 6c c6 85 ?? fc ff ff 6f c6 85 ?? fc ff ff 63 c6 85 ?? fc ff ff 00 } //1
		$a_02_1 = {64 a1 00 00 00 00 50 81 ec ?? ?? 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 ?? 50 8d 45 ?? 64 a3 00 00 00 00 b9 ?? ?? ?? ?? e8 ?? ?? ff ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}