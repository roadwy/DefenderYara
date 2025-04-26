
rule Trojan_Win32_Cryptinject_MK_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.MK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 85 ec fb ff ff 83 c2 04 88 1c 3e 88 7c 3e 01 88 4c 3e 02 83 c6 03 89 95 f0 fb ff ff 3b 10 } //1
		$a_01_1 = {c1 e8 10 30 04 0e 46 3b f7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}