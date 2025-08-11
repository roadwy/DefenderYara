
rule Trojan_Win32_Amadey_DA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 55 e1 8a c1 c0 ea 06 c0 e8 02 80 e1 03 88 45 e8 33 db 8a c5 c0 e1 04 c0 e8 04 80 e5 0f 02 c8 c0 e5 02 8d 47 01 88 4d e9 02 ea 89 45 e4 88 6d ea 85 c0 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}