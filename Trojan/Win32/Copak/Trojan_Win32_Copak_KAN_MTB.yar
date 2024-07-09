
rule Trojan_Win32_Copak_KAN_MTB{
	meta:
		description = "Trojan:Win32/Copak.KAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 33 01 d2 89 c2 f7 d0 81 e6 ?? ?? ?? ?? 21 c2 21 ca 81 ea ?? ?? ?? ?? 31 37 41 29 d0 47 48 89 c1 43 21 d1 f7 d2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}