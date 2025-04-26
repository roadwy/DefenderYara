
rule Ransom_Win32_Locky_A_MTB{
	meta:
		description = "Ransom:Win32/Locky.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 0c 24 8b 4d 08 8d 64 24 fc 33 0c 24 8b ff 33 c0 31 0c 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}