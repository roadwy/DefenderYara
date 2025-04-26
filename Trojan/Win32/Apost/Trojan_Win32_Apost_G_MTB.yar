
rule Trojan_Win32_Apost_G_MTB{
	meta:
		description = "Trojan:Win32/Apost.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 1c 38 eb [0-25] 80 f3 [0-25] 90 13 [0-0a] 80 f3 [0-15] 90 13 [0-0a] 88 1c 38 } //1
		$a_02_1 = {a7 8a 1c 38 [0-10] 90 13 80 f3 [0-15] 90 13 f6 d3 [0-10] 90 13 80 f3 [0-25] 90 13 88 1c 38 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}