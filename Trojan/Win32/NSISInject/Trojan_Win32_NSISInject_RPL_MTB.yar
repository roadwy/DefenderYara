
rule Trojan_Win32_NSISInject_RPL_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {54 61 6c 65 6c 69 64 65 6c 73 65 72 6e 65 73 5c 43 69 63 65 72 6f 6e 69 61 6e 5c 53 74 61 6e 64 6b 69 73 74 65 72 } //1 Talelidelsernes\Ciceronian\Standkister
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 4e 6f 6e 6f 62 76 69 6f 75 73 6e 65 73 73 5c 54 72 61 6e 73 73 68 69 70 5c 6c 61 75 72 62 72 6b 72 61 6e 73 65 6e } //1 Software\Nonobviousness\Transship\laurbrkransen
		$a_81_2 = {52 65 6e 74 65 62 65 6c 62 65 6e 65 2e 48 65 6d } //1 Rentebelbene.Hem
		$a_81_3 = {44 65 72 6f 75 74 65 72 73 2e 6c 6e 6b } //1 Derouters.lnk
		$a_81_4 = {52 69 6b 73 64 61 61 6c 64 65 72 2e 42 6f 6c } //1 Riksdaalder.Bol
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}