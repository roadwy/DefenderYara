
rule Trojan_Win32_Guildma_psyF_MTB{
	meta:
		description = "Trojan:Win32/Guildma.psyF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 7b 65 0e 66 c1 fd 0e 66 4b ad 0d 66 3a 5f 0e 66 b8 ac 0d 66 5a c2 0c 66 ec 9c 0d 66 ee f6 0e 66 71 3a 10 66 bf b6 0d 66 0d 3f 0e 66 62 3e 0e 66 86 f7 0e 66 86 f8 0e 66 fc b8 0d 66 6e 89 [0-20] 3c 0d 66 68 72 0e [0-20] 66 76 fe 0e 66 cb } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}