
rule Trojan_Win32_Convagent_AG_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 47 65 49 4d 70 6c 68 6e 6e 74 7a 71 66 74 49 70 } //1 AGeIMplhnntzqftIp
		$a_01_1 = {4f 6b 6f 78 6c 50 6f 71 61 6a 75 } //1 OkoxlPoqaju
		$a_01_2 = {50 48 54 61 4c 42 49 67 6a 76 70 4d 74 76 45 78 6a } //1 PHTaLBIgjvpMtvExj
		$a_01_3 = {5a 56 4b 6a 78 5a 68 47 78 73 73 4f 4f 55 6f 66 7a } //1 ZVKjxZhGxssOOUofz
		$a_01_4 = {6c 70 4e 68 44 72 57 42 72 65 65 47 58 42 4a 61 46 } //1 lpNhDrWBreeGXBJaF
		$a_01_5 = {66 6f 72 6b 32 2e 64 6c 6c } //1 fork2.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}