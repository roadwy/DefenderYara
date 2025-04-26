
rule Trojan_Win32_Backboot_CA_MTB{
	meta:
		description = "Trojan:Win32/Backboot.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 b5 80 c6 45 b6 89 c6 45 b7 8b c6 45 b8 8c c6 45 b9 78 c6 45 ba 83 c6 45 bb 58 c6 45 bc 83 c6 45 bd 83 c6 45 be 86 c6 45 bf 7a c6 45 c0 5c c6 45 c1 8f c6 45 c2 65 c6 45 c3 8c c6 45 c4 84 c6 45 c5 78 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}