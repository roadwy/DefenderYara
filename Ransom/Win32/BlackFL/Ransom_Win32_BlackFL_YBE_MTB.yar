
rule Ransom_Win32_BlackFL_YBE_MTB{
	meta:
		description = "Ransom:Win32/BlackFL.YBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 61 72 64 63 6f 72 65 20 62 6c 6f 77 6a 6f 62 } //1 hardcore blowjob
		$a_01_1 = {42 00 6c 00 61 00 63 00 6b 00 46 00 4c 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //1 BlackFL Ransomware
		$a_01_2 = {53 65 72 76 65 72 73 20 61 72 65 20 6c 6f 63 6b 65 64 } //1 Servers are locked
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}