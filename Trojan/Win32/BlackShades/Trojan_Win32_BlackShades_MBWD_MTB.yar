
rule Trojan_Win32_BlackShades_MBWD_MTB{
	meta:
		description = "Trojan:Win32/BlackShades.MBWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {38 74 40 00 9c 14 40 00 40 f0 34 00 00 ff ff ff 08 00 00 00 01 00 00 00 06 00 00 00 e9 00 00 00 bc 12 40 00 14 11 40 00 d0 10 40 00 78 00 00 00 80 00 00 00 8b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}