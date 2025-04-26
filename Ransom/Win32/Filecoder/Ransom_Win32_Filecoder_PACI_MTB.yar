
rule Ransom_Win32_Filecoder_PACI_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PACI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 52 8b 54 24 0c 8b 4c 24 08 81 c1 ff 00 00 00 29 d1 41 41 89 4c 24 08 5a 59 c2 04 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}