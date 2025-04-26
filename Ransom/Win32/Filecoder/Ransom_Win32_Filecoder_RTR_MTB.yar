
rule Ransom_Win32_Filecoder_RTR_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.RTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 01 33 02 2b 02 03 02 89 06 83 c2 04 47 8b c7 2b 45 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}