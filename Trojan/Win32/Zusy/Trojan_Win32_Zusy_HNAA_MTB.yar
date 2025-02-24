
rule Trojan_Win32_Zusy_HNAA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.HNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 78 70 6c 6f 72 65 72 00 55 70 64 61 74 65 48 6f 73 74 [0-a0] 00 4e 49 43 4b 20 [0-40] 55 53 45 52 20 } //3
		$a_01_1 = {25 73 3a 2a 3a 65 6e 61 62 6c 65 64 3a 40 73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 2d 31 } //2 %s:*:enabled:@shell32.dll,-1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}