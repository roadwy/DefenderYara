
rule Trojan_Win32_Zusy_BAG_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 a4 c1 e0 05 89 c2 8b 45 a4 01 c2 8b 45 a0 01 d0 89 45 a4 8b 45 a8 8d 50 01 89 55 a8 0f b6 00 0f be c0 89 45 a0 83 7d a0 00 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}