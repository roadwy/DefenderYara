
rule Ransom_Win32_GrandCrab_SA_MSR{
	meta:
		description = "Ransom:Win32/GrandCrab.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {39 32 2e 36 33 2e 31 39 37 2e 36 30 } //1 92.63.197.60
		$a_01_1 = {70 61 6b 6c 75 64 6b 6f 73 61 } //1 pakludkosa
		$a_01_2 = {31 32 33 2e 35 36 2e 32 32 38 2e 34 39 } //1 123.56.228.49
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}