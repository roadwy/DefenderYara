
rule Trojan_Win32_Cryptinject_R_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 fb f5 11 00 00 75 90 01 01 56 ff 15 90 01 04 8b 0d 90 01 04 8b 95 0c ef ff ff 69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 89 0d 90 01 04 c1 e8 10 30 04 17 47 3b fb 7c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}