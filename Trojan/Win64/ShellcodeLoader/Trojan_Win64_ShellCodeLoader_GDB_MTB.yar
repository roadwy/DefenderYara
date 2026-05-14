
rule Trojan_Win64_ShellCodeLoader_GDB_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeLoader.GDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4d 10 e8 42 67 02 00 48 39 45 f8 0f 92 c0 84 c0 74 22 48 8b 45 f8 48 89 c2 48 8b 4d 10 e8 97 bc 08 00 48 89 c2 0f b6 02 32 45 18 88 02 48 83 45 f8 01 eb ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}