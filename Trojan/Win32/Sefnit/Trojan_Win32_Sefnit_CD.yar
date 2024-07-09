
rule Trojan_Win32_Sefnit_CD{
	meta:
		description = "Trojan:Win32/Sefnit.CD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c8 8b ff 8a 14 01 80 f2 ?? 88 10 40 4f 75 f4 8b 06 b9 ?? ?? ?? ?? 39 48 f8 7c ca } //1
		$a_03_1 = {50 68 bb 01 00 00 68 ?? ?? ?? ?? 51 57 68 ?? ?? ?? ?? 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}