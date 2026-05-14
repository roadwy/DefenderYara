
rule Trojan_Win32_Zusy_LMY_MTB{
	meta:
		description = "Trojan:Win32/Zusy.LMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 db 83 f8 08 0f 45 d8 0f b6 44 1d e4 30 04 3a 8a 04 3a 8b 4e 10 8b 56 14 88 45 e0 3b ca } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}