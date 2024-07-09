
rule Trojan_Win32_Rozena_BD_MTB{
	meta:
		description = "Trojan:Win32/Rozena.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 01 8d 04 29 99 f7 7c 24 10 0f b6 82 [0-04] 30 41 01 8d 04 0b 99 8d 49 05 f7 7c 24 10 0f b6 82 [0-04] 30 41 fd 8d 04 0e 3d fa 00 00 00 7c } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}