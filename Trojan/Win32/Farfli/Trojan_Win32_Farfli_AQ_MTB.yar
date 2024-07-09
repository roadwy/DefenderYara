
rule Trojan_Win32_Farfli_AQ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {2c df 34 75 f8 6e 09 f8 0c 0e 9c 32 55 a4 4c 7a ef } //2
		$a_03_1 = {23 de 30 0a 8d 1d [0-04] fb 6b 0e ?? 19 e1 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}