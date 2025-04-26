
rule Trojan_Win32_Stelega_EAXC_MTB{
	meta:
		description = "Trojan:Win32/Stelega.EAXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {b1 96 f6 d2 2a d0 c0 c2 03 02 d0 f6 da 80 f2 2b 80 ea 58 f6 d2 32 d0 c0 c2 02 02 d0 32 d0 2a ca 32 c8 88 88 ?? ?? ?? ?? 40 3d 05 50 00 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}