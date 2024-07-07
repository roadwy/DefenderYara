
rule Trojan_Win32_CryptInject_MTO_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MTO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe c2 02 9c 15 16 10 00 00 8a 84 15 16 10 00 00 8a ac 1d 16 10 00 00 88 84 1d 16 10 00 00 88 ac 15 16 10 00 00 02 c5 47 8a 84 05 16 10 00 00 30 07 fe c9 4e 75 ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}