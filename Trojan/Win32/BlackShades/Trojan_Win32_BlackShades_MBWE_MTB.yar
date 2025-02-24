
rule Trojan_Win32_BlackShades_MBWE_MTB{
	meta:
		description = "Trojan:Win32/BlackShades.MBWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {f5 34 76 00 00 94 08 00 a4 00 fc } //2
		$a_01_1 = {4c 20 40 00 94 12 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 00 00 00 00 e9 00 00 00 20 11 40 00 20 11 40 00 e4 10 40 00 78 00 00 00 80 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}