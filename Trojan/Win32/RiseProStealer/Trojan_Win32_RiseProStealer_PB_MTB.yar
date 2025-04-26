
rule Trojan_Win32_RiseProStealer_PB_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 17 8b c3 8b d8 8b f6 33 f6 33 f6 8b de 33 f6 8b c3 33 f6 80 07 ?? 8b f6 8b db 8b d8 33 f0 33 db 33 f3 8b f3 33 de 33 c6 80 2f ?? 8b de 8b c0 8b d8 33 db 33 f3 8b c0 8b c6 33 f0 33 f3 f6 2f 47 e2 ab } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}