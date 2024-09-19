
rule Ransom_Win32_Revil_AK{
	meta:
		description = "Ransom:Win32/Revil.AK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a3 68 fb 48 00 a1 08 70 43 00 a3 38 ac 4b 00 33 c0 39 35 ec 41 49 00 76 1f 8b 0d 38 ac 4b 00 8a 8c 08 ?? ?? ?? ?? 8b 15 68 fb 48 00 88 0c 10 40 3b 05 ec 41 49 00 72 e1 68 ec 41 49 00 68 68 fb 48 00 e8 92 e6 ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}