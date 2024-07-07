
rule Trojan_Win32_Zenpak_BR_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 fe 81 e6 90 02 04 8b bd 90 02 04 8b 8d 90 02 04 8a 1c 0f 32 9c 35 90 02 04 8b b5 90 02 04 88 1c 0e 81 c1 01 00 00 00 8b b5 90 02 04 39 f1 8b b5 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}