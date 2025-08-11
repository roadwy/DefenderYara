
rule Trojan_Win32_Zusy_EZV_MTB{
	meta:
		description = "Trojan:Win32/Zusy.EZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f0 89 d0 c1 e0 02 01 d0 c1 e0 03 89 c2 8b 45 e0 01 d0 89 c2 8d 45 d4 89 44 24 04 89 14 24 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}