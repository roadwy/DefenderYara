
rule Trojan_Win32_Rootkit_C{
	meta:
		description = "Trojan:Win32/Rootkit.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 c7 45 a4 6e 00 66 c7 45 a6 6b 00 66 c7 45 aa 3e 00 66 c7 45 ac 33 00 66 c7 45 ae 36 00 66 c7 45 b0 30 00 66 c7 45 b2 3c 00 66 c7 45 b4 2f 00 66 89 55 b6 66 c7 45 b8 3e 00 } //1
		$a_01_1 = {68 40 1f 00 00 6a 02 ff 76 20 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}