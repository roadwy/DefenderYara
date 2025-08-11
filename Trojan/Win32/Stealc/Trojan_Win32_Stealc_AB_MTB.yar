
rule Trojan_Win32_Stealc_AB_MTB{
	meta:
		description = "Trojan:Win32/Stealc.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c9 ba 65 00 00 00 b8 6e 00 00 00 68 d0 63 51 00 66 89 0d e8 63 51 00 66 89 15 d2 63 51 00 66 a3 d6 63 51 00 ff 15 ?? ?? ?? ?? 68 b8 dd 43 00 50 c6 05 ba dd 43 00 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}