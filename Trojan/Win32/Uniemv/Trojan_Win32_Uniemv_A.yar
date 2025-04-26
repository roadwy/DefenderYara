
rule Trojan_Win32_Uniemv_A{
	meta:
		description = "Trojan:Win32/Uniemv.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {2e 70 68 70 3f 75 73 65 72 3d 25 73 26 69 64 3d [0-08] 26 74 79 70 65 3d ?? 26 68 61 73 68 72 61 74 65 3d 25 73 } //10
		$a_03_1 = {85 c0 75 11 68 60 ea 00 00 ff 15 ?? ?? ?? ?? 46 83 fe 05 7c e6 90 09 05 00 e8 } //1
		$a_03_2 = {ff d3 85 c0 7e 17 8a 45 ?? 88 84 35 ?? ?? ?? ?? 3c 0a 74 09 46 81 fe ff 1f 00 00 7c } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}