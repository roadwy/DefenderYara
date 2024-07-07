
rule Ransom_Win32_Crysis_CX_MTB{
	meta:
		description = "Ransom:Win32/Crysis.CX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 00 8d 85 7c bf ff ff 50 6a 05 6a 01 ff b5 58 f8 ff ff ff b5 74 f8 ff ff ff 15 78 22 42 00 8b 85 64 f4 ff ff 03 85 90 bf ff ff 8a 8d 8f bf ff ff 88 08 e9 70 } //1
		$a_01_1 = {55 8b ec 51 89 4d fc 8b 45 fc 8b 00 03 45 08 c9 c2 04 00 55 8b ec 51 51 89 4d f8 ff 75 08 e8 6d 30 00 00 59 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}