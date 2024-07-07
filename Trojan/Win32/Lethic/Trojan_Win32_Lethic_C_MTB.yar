
rule Trojan_Win32_Lethic_C_MTB{
	meta:
		description = "Trojan:Win32/Lethic.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b 07 41 0a c9 41 0f c0 cf 8a 4f 90 01 01 45 0f bf f8 66 41 81 f7 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}