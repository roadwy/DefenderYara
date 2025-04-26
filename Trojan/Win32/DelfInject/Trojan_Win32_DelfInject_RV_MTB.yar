
rule Trojan_Win32_DelfInject_RV_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.RV!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 07 88 07 8d 45 ec 8a 17 } //2
		$a_01_1 = {89 07 8b 03 8b 17 89 10 83 03 04 8b 03 83 38 00 75 a2 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}