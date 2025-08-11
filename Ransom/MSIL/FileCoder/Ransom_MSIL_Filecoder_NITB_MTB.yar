
rule Ransom_MSIL_Filecoder_NITB_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.NITB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 0b 00 00 0a 25 72 d3 00 00 70 6f ?? 00 00 0a 25 72 ed 00 00 70 6f ?? 00 00 0a 25 72 2d 00 00 70 6f ?? 00 00 0a 25 16 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 2a } //2
		$a_03_1 = {73 0b 00 00 0a 25 72 4d 01 00 70 6f ?? 00 00 0a 25 72 67 01 00 70 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 16 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 2a } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}