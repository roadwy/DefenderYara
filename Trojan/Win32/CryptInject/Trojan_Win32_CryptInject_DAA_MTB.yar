
rule Trojan_Win32_CryptInject_DAA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c4 0c b1 0b 33 c0 30 0c 30 40 80 c1 02 3d 04 78 00 00 72 f2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}