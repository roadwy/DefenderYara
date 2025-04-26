
rule Trojan_Win32_ValleyRat_MHS_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.MHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 04 49 8d 04 45 07 00 00 00 35 84 18 f1 ba 03 05 c8 f6 42 00 68 08 0a 43 00 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}