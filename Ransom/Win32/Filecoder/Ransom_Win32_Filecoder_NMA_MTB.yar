
rule Ransom_Win32_Filecoder_NMA_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.NMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d0 83 ec 14 85 c0 0f 85 ?? ?? 00 00 8b 45 f4 8d 55 88 89 54 24 14 8d 55 8c 89 54 24 10 } //2
		$a_01_1 = {73 6f 6d 65 73 6f 6d 65 57 61 72 5f 45 4f 46 } //1 somesomeWar_EOF
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}