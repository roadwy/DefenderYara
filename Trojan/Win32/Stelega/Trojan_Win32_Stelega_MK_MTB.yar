
rule Trojan_Win32_Stelega_MK_MTB{
	meta:
		description = "Trojan:Win32/Stelega.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b2 68 32 c8 2a d1 2a d0 c0 ca 02 32 d0 fe ca 02 d0 f6 d2 32 d0 d0 ca f6 da 32 d0 02 d0 d0 c2 80 f2 2c f6 d2 88 94 [0-05] 40 3d [0-02] 00 00 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}