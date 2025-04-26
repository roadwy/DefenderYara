
rule Ransom_Win32_Delta_MK_MTB{
	meta:
		description = "Ransom:Win32/Delta.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {49 6e 66 6f 2e 68 74 61 } //Info.hta  1
		$a_80_1 = {2e 5b 44 65 6c 74 61 5d } //.[Delta]  1
		$a_80_2 = {44 65 6c 74 61 20 45 6e 63 72 79 70 74 } //Delta Encrypt  1
		$a_80_3 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c } //vssadmin.exe delete shadows /all  1
		$a_80_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 64 65 6c 6f 67 2e 63 6d 64 } //C:\Windows\delog.cmd  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}