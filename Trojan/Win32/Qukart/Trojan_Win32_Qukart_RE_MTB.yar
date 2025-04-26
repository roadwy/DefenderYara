
rule Trojan_Win32_Qukart_RE_MTB{
	meta:
		description = "Trojan:Win32/Qukart.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 5f 5e 5b 89 ec 5d c3 fc 55 89 e5 83 ec 08 53 56 57 55 8b 5d 0c 8b 45 08 a3 8c d0 42 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}