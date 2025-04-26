
rule Trojan_Win32_AveMariaRat_MI_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRat.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 07 33 d2 88 44 24 10 b9 ?? ?? ?? ?? 8a 47 01 88 44 24 11 8a 47 02 88 44 24 12 8a 47 03 88 44 24 13 c7 07 ?? ?? ?? ?? 8b 01 f7 d0 85 c0 74 ?? 88 04 2a 83 e9 04 42 81 f9 ?? ?? ?? ?? 7d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}