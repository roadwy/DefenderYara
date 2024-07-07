
rule Trojan_Win32_Copak_VU_MTB{
	meta:
		description = "Trojan:Win32/Copak.VU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {21 c0 29 c0 e8 90 01 04 81 e8 90 01 04 29 db 31 0e 09 db 46 29 c3 39 d6 75 df 21 db 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}