
rule Trojan_Win32_Ekstak_CCJS_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CCJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a d1 8b 3d 34 e0 4c 00 22 d0 a1 30 e0 4c 00 80 f2 ?? 56 88 15 ?? e0 4c 00 8b d0 c1 ea 05 23 fa 33 d2 83 e0 08 8a d1 0f af c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}