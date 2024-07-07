
rule Trojan_Win32_CryptInject_SL_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 61 6e 5c 77 73 64 6c 5c 70 61 79 70 61 6c } //5 dan\wsdl\paypal
		$a_01_1 = {53 77 61 74 56 65 6c 61 6d 65 6e 2e 64 6c 6c } //1 SwatVelamen.dll
		$a_01_2 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 53 77 61 74 56 65 6c 61 6d 65 6e 2c 50 72 65 74 6f 72 } //5 %%\rundll32.exe SwatVelamen,Pretor
		$a_01_3 = {77 65 62 73 65 72 76 69 63 65 73 } //1 webservices
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1) >=12
 
}