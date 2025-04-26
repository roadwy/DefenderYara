
rule Ransom_Win32_Gandcrab_RPA_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b cf 8b c7 c1 e9 05 03 4b 0c c1 e0 04 03 43 08 33 c8 8d 04 3a 33 c8 2b f1 8b ce 8b c6 c1 e9 05 03 4b 04 c1 e0 04 03 03 33 c8 8d 04 32 33 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}