
rule Ransom_Win32_FileCoder_NB_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.NB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 fd d0 ff ff 83 c0 0c 5a c7 40 f8 01 00 00 00 89 50 fc 66 c7 04 50 00 00 66 c7 40 f6 02 00 8b 15 80 69 4f 00 66 89 50 f4 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}