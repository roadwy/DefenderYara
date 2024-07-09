
rule PWS_Win32_Reveton_A{
	meta:
		description = "PWS:Win32/Reveton.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 40 14 26 5a e8 ?? ?? ?? ?? 8b 85 ?? ?? ff ff 66 ba bb 01 e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}