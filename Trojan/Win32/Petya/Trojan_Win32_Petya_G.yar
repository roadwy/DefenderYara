
rule Trojan_Win32_Petya_G{
	meta:
		description = "Trojan:Win32/Petya.G,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 e6 3c 3d 35 03 e8 90 01 04 81 f2 ae 51 f1 08 85 c0 70 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}