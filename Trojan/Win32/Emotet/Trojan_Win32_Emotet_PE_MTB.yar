
rule Trojan_Win32_Emotet_PE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_00_0 = {2b 11 f7 da 83 c1 04 83 ea 23 01 f2 83 ea 01 31 f6 29 d6 f7 de c6 07 00 01 17 8d 7f 04 8d 5b 04 2e eb } //5
		$a_02_1 = {11 23 67 45 90 02 10 11 23 67 45 90 02 10 11 23 67 45 90 02 10 00 00 00 00 90 02 10 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*5+(#a_02_1  & 1)*1) >=6
 
}