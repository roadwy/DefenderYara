
rule Trojan_Win32_Redline_GPAH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GPAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b de 8b c3 33 f6 33 f6 33 c0 33 d8 33 f0 8b d8 f6 17 33 c6 8b de 8b f3 33 db 8b f0 8b f0 33 d8 8b c6 8b c3 80 2f ?? 33 f6 8b c6 8b f3 8b f0 33 c0 33 c6 8b f0 33 c0 33 c6 80 07 ?? 33 c3 33 f0 8b c3 33 d8 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}