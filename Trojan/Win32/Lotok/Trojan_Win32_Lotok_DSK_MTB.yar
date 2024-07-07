
rule Trojan_Win32_Lotok_DSK_MTB{
	meta:
		description = "Trojan:Win32/Lotok.DSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 40 33 ff 89 45 e8 57 8a 04 10 8a 14 0e 32 d0 88 14 0e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}