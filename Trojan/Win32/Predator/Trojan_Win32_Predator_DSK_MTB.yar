
rule Trojan_Win32_Predator_DSK_MTB{
	meta:
		description = "Trojan:Win32/Predator.DSK!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 41 03 8a d0 8a d8 80 e2 f0 80 e3 fc c0 e2 02 0a 11 c0 e0 06 0a 41 02 c0 e3 04 0a 59 01 8b 4d f4 88 14 0f 47 88 1c 0f } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}