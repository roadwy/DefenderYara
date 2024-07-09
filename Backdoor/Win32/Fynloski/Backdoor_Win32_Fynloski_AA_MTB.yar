
rule Backdoor_Win32_Fynloski_AA_MTB{
	meta:
		description = "Backdoor:Win32/Fynloski.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4a 71 5a 74 46 69 30 48 42 52 4b 6e 74 32 51 4b 32 6a 34 54 79 58 56 71 62 30 7a 4e 57 48 57 57 55 66 2e 64 6c 6c } //1 JqZtFi0HBRKnt2QK2j4TyXVqb0zNWHWWUf.dll
		$a_02_1 = {89 ff 4b 75 fb 90 0a 5f 00 6a 00 6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? 4b 75 f0 [0-4f] bb ?? ?? ?? ?? 89 ff 4b 75 fb } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}