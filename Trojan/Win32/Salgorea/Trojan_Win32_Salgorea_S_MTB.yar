
rule Trojan_Win32_Salgorea_S_MTB{
	meta:
		description = "Trojan:Win32/Salgorea.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 9e 05 81 c7 45 90 01 01 4f 91 31 af c7 45 90 01 01 cf a0 8f dc c7 45 90 01 01 53 69 47 38 c7 45 90 01 01 f3 c8 bd b6 c7 45 90 01 01 b9 df 47 8f c7 45 90 01 01 22 7a f2 ce c7 45 90 01 01 61 c8 a5 a1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}