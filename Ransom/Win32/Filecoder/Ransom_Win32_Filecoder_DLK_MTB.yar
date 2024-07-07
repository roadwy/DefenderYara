
rule Ransom_Win32_Filecoder_DLK_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.DLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4a fe 0f b6 42 ff c1 e1 08 0b c8 0f b6 02 c1 e1 08 8d 52 04 0b c8 0f b6 42 fd c1 e1 08 0b c8 89 4c bc 5c 47 83 ff 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}