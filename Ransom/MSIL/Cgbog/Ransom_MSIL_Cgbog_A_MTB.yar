
rule Ransom_MSIL_Cgbog_A_MTB{
	meta:
		description = "Ransom:MSIL/Cgbog.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 25 26 28 ?? ?? 00 06 25 26 0d 00 09 28 ?? ?? 00 06 25 26 28 ?? ?? 00 06 25 26 13 07 38 10 02 00 00 11 07 28 ?? ?? 00 06 25 26 28 ?? ?? 00 06 25 26 13 04 00 7e ?? ?? 00 04 0a 02 11 04 20 } //2
		$a_01_1 = {52 65 67 69 73 74 72 79 4b 65 79 } //1 RegistryKey
		$a_01_2 = {44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 DebuggerPresent
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}