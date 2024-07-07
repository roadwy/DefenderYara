
rule Trojan_BAT_Stealer_MVB_MTB{
	meta:
		description = "Trojan:BAT/Stealer.MVB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 61 73 73 47 72 61 62 62 65 72 2e 65 78 65 } //2 PassGrabber.exe
		$a_01_1 = {32 61 64 37 31 31 63 38 2d 66 61 65 36 2d 34 30 65 66 2d 38 33 64 35 2d 61 33 66 31 36 38 64 32 62 34 65 37 } //1 2ad711c8-fae6-40ef-83d5-a3f168d2b4e7
		$a_01_2 = {43 61 6c 63 75 6c 61 74 65 4c 69 73 74 65 6e 65 72 } //1 CalculateListener
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}