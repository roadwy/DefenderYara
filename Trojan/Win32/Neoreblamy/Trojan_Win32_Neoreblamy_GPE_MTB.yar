
rule Trojan_Win32_Neoreblamy_GPE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {75 55 50 71 75 62 6f 51 62 6f 65 } //3 uUPquboQboe
		$a_81_1 = {47 73 64 48 74 58 4b 6d 67 4d 70 5a 4f 67 6e 6a 78 5a 42 7a 65 5a 7a 54 4d 7a 58 47 4a 4b 64 45 } //2 GsdHtXKmgMpZOgnjxZBzeZzTMzXGJKdE
		$a_81_2 = {6a 47 68 56 79 44 70 63 57 51 4f 75 67 6c 4e 42 58 } //1 jGhVyDpcWQOuglNBX
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}