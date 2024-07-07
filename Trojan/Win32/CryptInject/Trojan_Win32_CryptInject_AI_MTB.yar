
rule Trojan_Win32_CryptInject_AI_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 00 40 61 6c 74 61 74 65 40 30 00 40 70 6c 75 73 54 6f 6b 65 6e 41 66 74 65 72 40 34 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}