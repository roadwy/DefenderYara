
rule Trojan_Win32_NSISInject_SLF_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.SLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {6f 76 65 72 73 6b 75 65 64 65 73 2e 63 68 61 } //1 overskuedes.cha
		$a_81_1 = {74 77 69 74 2e 6a 65 6e } //1 twit.jen
		$a_81_2 = {64 65 6e 6f 74 61 74 69 6f 6e 65 6e 2e 75 6e 72 } //1 denotationen.unr
		$a_81_3 = {5c 72 64 62 67 65 6e 73 5c 68 61 6c 69 66 61 78 2e 64 6c 6c } //1 \rdbgens\halifax.dll
		$a_81_4 = {5c 66 65 74 61 65 6e 73 5c 73 63 61 70 68 69 6f 70 75 73 2e 41 61 6e 33 31 } //1 \fetaens\scaphiopus.Aan31
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}