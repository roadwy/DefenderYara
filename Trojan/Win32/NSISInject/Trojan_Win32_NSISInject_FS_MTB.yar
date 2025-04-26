
rule Trojan_Win32_NSISInject_FS_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 6f 66 74 77 61 72 65 5c 42 65 73 6c 61 67 73 6d 65 64 65 6e 65 73 5c 41 67 70 61 69 74 69 63 5c 4c 75 66 74 66 61 72 74 6a 65 72 6e 65 73 } //1 Software\Beslagsmedenes\Agpaitic\Luftfartjernes
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 53 74 6a 6b 6f 72 74 6c 67 6e 69 6e 67 65 6e 73 } //1 Software\Stjkortlgningens
		$a_81_2 = {5c 43 61 6c 65 62 36 32 5c 43 61 6e 63 65 6c 6c 6f 75 73 2e 55 6e 61 } //1 \Caleb62\Cancellous.Una
		$a_81_3 = {5c 62 6e 73 6b 72 69 66 74 65 74 5c 54 65 6b 73 74 61 6e 6d 72 6b 6e 69 6e 67 65 72 73 2e 48 65 6d } //1 \bnskriftet\Tekstanmrkningers.Hem
		$a_81_4 = {5c 46 61 73 74 72 65 6e 65 73 5c 66 61 63 61 64 65 72 73 2e 46 69 6c } //1 \Fastrenes\facaders.Fil
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}