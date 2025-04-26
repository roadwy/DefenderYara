
rule Trojan_Win32_Rhadamanthys_TBM_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.TBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c8 0f ca 0b d7 33 ca 33 4c 9c 10 33 ce 89 4c 9c 20 43 83 fb 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}