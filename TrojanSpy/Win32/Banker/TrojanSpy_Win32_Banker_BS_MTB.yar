
rule TrojanSpy_Win32_Banker_BS_MTB{
	meta:
		description = "TrojanSpy:Win32/Banker.BS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 f6 2b 37 f7 de 83 ef fc 83 ee 34 c1 ce 08 29 d6 83 ee 01 29 d2 29 f2 f7 da c1 c2 09 d1 ca 6a ff 8f 01 21 31 83 e9 fc 83 eb 03 8d 5b ff 83 fb 00 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}