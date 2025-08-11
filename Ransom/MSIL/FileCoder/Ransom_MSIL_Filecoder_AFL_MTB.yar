
rule Ransom_MSIL_Filecoder_AFL_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.AFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 20 00 01 00 00 6f ?? 00 00 0a 00 07 20 80 00 00 00 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 03 04 20 50 c3 00 00 73 ?? 00 00 0a 0c 07 08 07 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}