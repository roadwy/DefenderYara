
rule Trojan_Win64_CryptInject_GKN_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.GKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 9c 48 81 ec 08 00 00 00 0f ae 1c 24 e8 00 00 00 00 5d 48 81 ed 33 00 00 00 48 81 ed 30 e3 90 01 81 fa 01 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}