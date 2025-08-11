
rule Trojan_Win32_PonyStealer_AHB_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 76 f2 0f fa f2 0f 6f ff 41 0f eb d8 0f 71 f0 02 0f d5 d2 ff 73 2c 66 0f 74 c1 66 0f fe d9 0f fc ff 31 0c 24 66 0f 76 f2 0f fa f2 0f 6f ff 5a 0f eb d8 0f 71 f0 02 0f d5 d2 83 fa 00 75 } //3
		$a_01_1 = {48 66 0f 74 c1 66 0f fe d9 0f fc ff 48 66 0f 76 f2 0f fa f2 0f 6f ff 48 0f eb d8 0f 71 f0 02 0f d5 d2 33 14 03 66 0f 74 c1 66 0f fe d9 0f fc ff e8 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}