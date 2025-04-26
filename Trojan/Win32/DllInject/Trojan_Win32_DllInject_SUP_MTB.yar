
rule Trojan_Win32_DllInject_SUP_MTB{
	meta:
		description = "Trojan:Win32/DllInject.SUP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 ff 30 64 89 20 8b c3 e8 98 b8 fd ff 50 e8 52 69 fe ff 89 45 f8 33 c0 5a 59 59 64 89 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}