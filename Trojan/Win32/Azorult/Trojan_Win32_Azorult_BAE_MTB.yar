
rule Trojan_Win32_Azorult_BAE_MTB{
	meta:
		description = "Trojan:Win32/Azorult.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c0 2b 07 f7 d8 8d 7f 04 f7 d0 f8 83 d0 df 8d 40 ff 29 d0 89 c2 89 06 83 ee fc f8 83 d1 fc } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}