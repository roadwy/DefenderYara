
rule Trojan_Win32_RedLineStealer_SA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {5c 10 40 00 46 3b 35 90 01 04 72 cd 90 09 26 00 a1 90 01 04 8a 84 30 3b 2d 0b 00 8b 0d 90 01 04 88 04 31 81 3d 90 01 04 92 02 00 00 75 90 01 01 57 57 57 ff 15 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}