
rule Ransom_Win32_Cerber_PAFY_MTB{
	meta:
		description = "Ransom:Win32/Cerber.PAFY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {6b c0 00 85 c0 74 ?? b6 56 8a d0 8a d0 0f ac ea 2a 4e 4e 0f c0 f2 0f be f4 0f b3 ce eb } //2
		$a_01_1 = {0f be f4 0f bd f1 84 e5 80 ee 11 b2 9a 2a f4 8a f4 80 ca d2 0f c0 f2 b6 56 eb } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}