
rule Ransom_Win32_Conti_MTB{
	meta:
		description = "Ransom:Win32/Conti!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 75 08 8b 7d 0c 8b 55 10 b1 01 ac } //1
		$a_03_1 = {aa 4a 0f 85 90 01 02 ff ff 8b ec 5d c2 0c 00 90 00 } //1
		$a_01_2 = {32 c1 2a c1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}