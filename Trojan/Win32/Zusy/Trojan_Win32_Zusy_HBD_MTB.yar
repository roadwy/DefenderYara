
rule Trojan_Win32_Zusy_HBD_MTB{
	meta:
		description = "Trojan:Win32/Zusy.HBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 74 24 10 ff 74 24 10 83 04 24 05 ?? ?? ?? ?? ?? 8f 44 24 28 8f 44 24 28 ff 74 24 08 ff 74 24 08 8d 44 24 2c 8b 10 29 14 24 8b 50 04 19 54 24 04 8f 44 24 30 8f 44 24 30 ff 74 24 30 ff 74 24 30 5b 5f 83 ff 00 7f 0b 7c 05 83 fb 05 77 04 ?? c0 eb 05 } //10
		$a_01_1 = {89 44 24 34 8b 44 24 2c 50 ff 74 24 38 ff 74 24 08 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}