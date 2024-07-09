
rule Trojan_Win32_Copak_D_MTB{
	meta:
		description = "Trojan:Win32/Copak.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 37 47 89 ca 39 c7 90 09 0c 00 be ?? ?? ?? ?? 09 d1 e8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}