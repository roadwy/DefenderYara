
rule Ransom_Win32_Conti_ZE{
	meta:
		description = "Ransom:Win32/Conti.ZE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba 15 00 00 00 c7 45 ec b9 07 a2 25 c7 45 f0 f3 dd 60 46 c7 45 f4 8e e9 76 e5 c7 45 f8 8c 74 06 3e e8 90 01 04 83 c4 08 8d 4d e8 6a 00 6a 00 51 6a 04 68 90 01 04 6a 10 8d 4d ec 51 68 06 00 00 c8 56 ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}