
rule Ransom_Win32_Beast_YAP_MTB{
	meta:
		description = "Ransom:Win32/Beast.YAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 54 06 04 8b 0e 02 c8 32 ca 88 4c 06 04 40 3d } //1
		$a_01_1 = {34 74 88 44 24 16 8b 44 24 10 04 03 88 44 24 17 8b 44 24 10 04 04 34 61 88 44 24 18 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10) >=11
 
}