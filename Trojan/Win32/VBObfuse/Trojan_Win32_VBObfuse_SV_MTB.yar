
rule Trojan_Win32_VBObfuse_SV_MTB{
	meta:
		description = "Trojan:Win32/VBObfuse.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 00 59 00 69 00 57 00 37 00 72 00 6e 00 42 00 4d 00 52 00 65 00 55 00 72 00 70 00 62 00 79 00 6b 00 79 00 41 00 56 00 7a 00 56 00 31 00 30 00 31 00 } //1 RYiW7rnBMReUrpbykyAVzV101
	condition:
		((#a_01_0  & 1)*1) >=1
 
}