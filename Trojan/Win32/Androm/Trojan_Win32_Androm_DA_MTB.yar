
rule Trojan_Win32_Androm_DA_MTB{
	meta:
		description = "Trojan:Win32/Androm.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 41 41 41 41 [0-04] 59 [0-04] 46 [0-04] 8b 17 [0-04] 31 f2 66 ?? ?? ?? ?? 39 ca 75 ?? [0-20] b9 ?? ?? ?? ?? [0-06] 83 e9 04 [0-04] 8b 14 0f [0-04] 56 [0-04] 33 14 24 [0-04] 5e [0-04] 89 14 08 [0-04] 83 f9 00 7f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}