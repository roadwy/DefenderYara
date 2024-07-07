
rule Ransom_Win32_FileCoder_MV_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 c3 0c 87 d7 2b cf 23 d3 33 f9 0b ca 23 d7 0b cb 87 d3 33 d9 } //1
		$a_01_1 = {32 c2 88 07 90 46 47 90 49 83 f9 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}