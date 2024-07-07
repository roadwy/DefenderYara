
rule Ransom_Win32_Magniber_AB_MTB{
	meta:
		description = "Ransom:Win32/Magniber.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 0c e9 90 0a 05 00 8b 4d 0c 90 13 ac 90 13 02 c3 90 13 32 c3 90 13 c0 c8 90 01 01 90 13 aa 90 13 49 90 13 0f 85 90 01 04 90 13 5e 90 13 5f 90 13 5a 90 13 59 90 13 5b 90 13 c9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}