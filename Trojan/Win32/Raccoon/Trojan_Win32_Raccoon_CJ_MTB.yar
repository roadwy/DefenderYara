
rule Trojan_Win32_Raccoon_CJ_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.CJ!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f1 8b ce c1 e1 04 03 4d ec 8b c6 c1 e8 05 03 45 f0 8d 14 37 33 ca 33 c8 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}