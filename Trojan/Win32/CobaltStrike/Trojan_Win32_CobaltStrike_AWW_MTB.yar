
rule Trojan_Win32_CobaltStrike_AWW_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.AWW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 c0 40 0f 28 ca 66 0f ef c8 0f 11 49 a0 0f 28 ca 0f 10 41 b0 66 0f ef c2 0f 11 41 b0 0f 10 41 c0 66 0f ef c2 0f 11 41 c0 0f 10 41 d0 66 0f ef c8 0f 11 49 d0 3b c7 72 c0 } //1
		$a_01_1 = {46 58 56 44 45 53 44 41 } //1 FXVDESDA
		$a_01_2 = {53 79 73 74 65 6d 2e 57 65 62 2e 6e 69 2e 64 6c 6c } //1 System.Web.ni.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}