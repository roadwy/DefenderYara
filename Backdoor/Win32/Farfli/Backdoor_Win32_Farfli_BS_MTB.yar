
rule Backdoor_Win32_Farfli_BS_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 80 34 08 b9 03 c1 41 3b cb 7c } //3
		$a_00_1 = {73 5c 25 73 61 69 72 2e 64 6c 6c } //2 s\%sair.dll
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*2) >=5
 
}