
rule Trojan_Win32_Kryptik_GB_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.GB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 fb 29 0f 86 c2 00 00 00 83 fb 41 76 24 8b ce 8b c3 8b 75 0c 85 f6 0f 45 ce 33 d2 f7 f1 33 d2 b9 ab ff e3 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}