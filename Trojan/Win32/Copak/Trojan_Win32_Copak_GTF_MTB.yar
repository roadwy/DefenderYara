
rule Trojan_Win32_Copak_GTF_MTB{
	meta:
		description = "Trojan:Win32/Copak.GTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {bf d8 85 40 00 81 e8 90 01 04 e8 90 01 04 01 c0 31 39 81 c6 90 01 04 09 c0 81 c1 90 01 04 81 c0 90 01 04 39 d1 75 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}