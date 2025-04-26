
rule Ransom_Win32_Ryuk_BS_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 6a 23 33 d2 5b 8d 0c 06 8b c6 f7 f3 8b 44 24 ?? 8a 04 02 30 01 46 3b 74 24 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}