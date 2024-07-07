
rule Trojan_Win32_RedLine_RDCJ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 8c 00 00 0a 25 08 6f 8d 00 00 0a 25 17 6f 8e 00 00 0a 25 18 6f 8f 00 00 0a 25 06 6f 90 00 00 0a 6f 91 00 00 0a 07 16 07 8e 69 6f 92 00 00 0a 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}