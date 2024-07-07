
rule Trojan_Win32_CtorIrpt_AD_MTB{
	meta:
		description = "Trojan:Win32/CtorIrpt.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {fc ff ff 56 c6 85 90 01 01 fc ff ff 69 c6 85 90 01 01 fc ff ff 72 c6 85 90 01 01 fc ff ff 74 c6 85 90 01 01 fc ff ff 75 c6 85 90 01 01 fc ff ff 61 c6 85 90 01 01 fc ff ff 6c c6 85 90 01 01 fc ff ff 41 c6 85 90 01 01 fc ff ff 6c c6 85 90 01 01 fc ff ff 6c c6 85 90 01 01 fc ff ff 6f c6 85 90 01 01 fc ff ff 63 c6 85 90 01 01 fc ff ff 00 90 00 } //1
		$a_02_1 = {64 a1 00 00 00 00 50 81 ec 90 01 02 00 00 a1 90 01 04 33 c5 89 45 90 01 01 50 8d 45 90 01 01 64 a3 00 00 00 00 b9 90 01 04 e8 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}