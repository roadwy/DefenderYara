
rule Trojan_Win32_Farfli_U_MTB{
	meta:
		description = "Trojan:Win32/Farfli.U!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6d 4d c1 50 90 01 02 c0 bf 90 01 05 24 90 01 01 fd ad 22 ff 69 a6 90 01 08 3b c4 ce f8 58 d4 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}