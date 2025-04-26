
rule Trojan_Win32_Injector_DE_MTB{
	meta:
		description = "Trojan:Win32/Injector.DE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 71 07 30 60 87 5f 20 ae 8b 03 6e 47 a5 22 24 0b 16 6c 44 80 ac 5b 3a fd 9d b6 2c 55 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}