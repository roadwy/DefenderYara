
rule Trojan_Win32_Zenpak_CCIO_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 48 89 c2 42 8d 05 ?? ?? ?? ?? 01 38 e8 ?? ?? ?? ?? c3 40 8d 05 ?? ?? ?? ?? 89 28 4a ba 09 00 00 00 40 89 d8 50 8f 05 ?? ?? ?? ?? 48 40 89 f0 50 8f 05 ?? ?? ?? ?? b9 02 00 00 00 e2 c1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}