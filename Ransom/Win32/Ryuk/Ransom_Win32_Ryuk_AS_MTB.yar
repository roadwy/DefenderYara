
rule Ransom_Win32_Ryuk_AS_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ff 8b 15 90 01 04 a1 90 01 04 89 02 90 09 22 00 a1 90 01 04 31 0d 90 01 06 c7 05 90 01 08 a1 90 01 04 01 05 90 00 } //1
		$a_00_1 = {4a 6f 68 6e 44 6f 65 } //1 JohnDoe
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}