
rule Ransom_Win32_Ryuk_AA{
	meta:
		description = "Ransom:Win32/Ryuk.AA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 00 79 00 75 00 6b 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //1 RyukReadMe.txt
	condition:
		((#a_01_0  & 1)*1) >=1
 
}