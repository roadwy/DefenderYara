
rule Trojan_Win32_Injector_KKB_MTB{
	meta:
		description = "Trojan:Win32/Injector.KKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 87 00 b0 00 10 8a 08 c0 c9 03 32 8a ?? ?? ?? ?? 6a 0c 88 08 8d 42 01 99 59 f7 f9 47 3b fe } //20
		$a_01_1 = {8d 45 fc 50 6a 40 56 be 00 b0 00 10 56 ff 15 34 80 00 10 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}