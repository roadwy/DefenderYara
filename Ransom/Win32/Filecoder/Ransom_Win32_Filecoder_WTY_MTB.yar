
rule Ransom_Win32_Filecoder_WTY_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.WTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 17 00 00 00 8b 55 08 83 c2 38 89 95 1c ff ff ff c7 85 14 ff ff ff 08 40 00 00 6a 08 8d 85 14 ff ff ff 50 8d 8d 64 ff ff ff 51 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}