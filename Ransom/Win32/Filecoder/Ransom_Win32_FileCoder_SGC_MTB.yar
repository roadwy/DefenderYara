
rule Ransom_Win32_FileCoder_SGC_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.SGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {a3 34 96 71 00 a1 34 96 71 00 a3 58 dc 70 00 33 c0 a3 5c dc 70 00 33 c0 a3 60 dc 70 00 8d 43 08 a3 68 dc 70 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}