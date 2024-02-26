
rule Trojan_Win64_CryptInject_TB_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.TB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 0f b6 14 02 8d 48 01 83 e1 03 d2 ca 41 88 14 00 48 83 c0 01 49 39 c1 75 e6 48 83 c4 28 49 ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}