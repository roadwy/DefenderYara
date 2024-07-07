
rule Ransom_Win32_FileCoder_MP_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e9 31 05 00 00 90 32 4d 0c 90 e9 42 02 00 00 50 90 e9 a6 03 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}