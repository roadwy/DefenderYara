
rule Trojan_Win32_Rhadamanthys_CA_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c1 8b 4d f4 89 55 f4 8a 44 18 03 32 45 ff 88 41 06 8b ca 8b 47 04 40 c1 e0 04 3b f0 8a 45 fe } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}