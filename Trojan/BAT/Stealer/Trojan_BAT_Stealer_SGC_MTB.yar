
rule Trojan_BAT_Stealer_SGC_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SGC!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 74 65 6d 70 25 5c 47 65 74 41 64 6d 69 6e 2e 76 62 73 } //1 %temp%\GetAdmin.vbs
		$a_01_1 = {73 74 61 72 74 20 2f 42 20 63 61 6c 6c 20 4f 42 46 32 30 78 2d 73 74 65 61 6c 65 72 2e 62 61 74 } //1 start /B call OBF20x-stealer.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}