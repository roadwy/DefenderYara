
rule Trojan_Win32_Scar_RC_MTB{
	meta:
		description = "Trojan:Win32/Scar.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5e 5b 31 db 8a 06 3c ff 75 02 ff e5 31 c0 51 50 31 c0 } //1
		$a_01_1 = {31 c0 50 31 c0 31 c9 41 40 d3 e0 56 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}