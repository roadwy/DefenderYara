
rule Ransom_Win32_Genasom_W{
	meta:
		description = "Ransom:Win32/Genasom.W,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 3b 00 00 00 ?? 2b ?? 53 c6 84 24 ?? ?? 00 00 e8 90 09 04 00 6a 05 } //1
		$a_01_1 = {c6 00 41 c6 40 01 64 c6 40 02 6a c6 40 03 75 c6 40 04 73 c6 40 05 74 c6 40 06 54 c6 40 07 6f c6 40 08 6b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}