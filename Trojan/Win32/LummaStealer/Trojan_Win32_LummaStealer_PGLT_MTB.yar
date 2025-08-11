
rule Trojan_Win32_LummaStealer_PGLT_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PGLT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b c8 c1 e2 ?? 8b 44 24 ?? 33 cd 33 6c 24 ?? 0b fa 89 4c 24 ?? 33 fe 8b 4c 24 ?? 83 e8 ?? 33 74 24 ?? 83 c1 ?? 83 6c 24 ?? ?? 89 4c 24 ?? 89 44 24 ?? 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_LummaStealer_PGLT_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.PGLT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be f9 8d 5b ?? 69 f7 ?? ?? ?? ?? c1 ce ?? 8b d6 8b ce c1 ea ?? c1 e1 ?? 33 d1 8a 0b 33 d6 69 d2 ?? ?? ?? ?? 33 55 ?? c1 ca ?? 81 c2 ?? ?? ?? ?? 8d 14 92 33 d7 33 d0 89 55 ?? 84 c9 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}