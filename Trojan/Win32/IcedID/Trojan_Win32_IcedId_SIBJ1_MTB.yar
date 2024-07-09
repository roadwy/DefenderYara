
rule Trojan_Win32_IcedId_SIBJ1_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {57 68 65 6e 62 6f 79 5c 74 65 6e 6b 65 70 74 5c 45 61 72 6c 79 56 61 6c 75 65 5c 63 6f 75 6c 64 2e 70 64 62 } //1 Whenboy\tenkept\EarlyValue\could.pdb
		$a_03_1 = {83 c6 04 8d [0-10] 81 fe ?? ?? ?? ?? 90 18 [0-3a] 8b 15 ?? ?? ?? ?? [0-0a] 8b ac 32 ?? ?? ?? ?? [0-5a] a1 90 1b 04 81 c5 ?? ?? ?? ?? [0-0a] 89 ac 30 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}