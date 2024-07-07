
rule Trojan_Win32_Zusy_FXB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.FXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 45 c4 88 44 3e 06 8a 45 c5 88 44 3e 05 8a 45 c6 88 44 3e 04 8a 45 c7 88 44 3e 03 8a 45 c8 88 44 3e 02 8a 45 c9 88 44 3e 01 8a 45 ca 88 04 3e 8b 75 d4 81 c6 20 00 00 00 8b 7d e0 39 fe 89 75 d8 0f 85 39 fe ff ff } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}