
rule Trojan_Win32_Nitol_B_MTB{
	meta:
		description = "Trojan:Win32/Nitol.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 ff c5 f8 49 d1 c5 44 3b d9 41 f6 c1 ?? 49 81 c5 ?? ?? ?? ?? 80 fd ?? 49 81 f5 ?? ?? ?? ?? f5 4d 33 f5 f5 41 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}