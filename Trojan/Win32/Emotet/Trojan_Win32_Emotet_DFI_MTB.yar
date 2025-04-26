
rule Trojan_Win32_Emotet_DFI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 03 c1 99 b9 8e 0a 00 00 f7 f9 0f b6 94 15 ?? ?? ?? ?? 30 53 ff } //1
		$a_81_1 = {43 35 58 70 65 6f 7a 53 48 6e 56 63 61 5a 5a 74 71 32 4c 34 65 66 41 34 33 4a 34 6d 67 30 51 32 6f 54 52 54 57 74 46 49 } //1 C5XpeozSHnVcaZZtq2L4efA43J4mg0Q2oTRTWtFI
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}