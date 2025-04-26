
rule Trojan_Win32_Bamital_H{
	meta:
		description = "Trojan:Win32/Bamital.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 c7 05 0e 30 00 10 72 65 89 45 fc 68 1c 30 00 10 68 2a 30 00 10 e8 87 ff ff ff 8b d0 8d 45 e4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}