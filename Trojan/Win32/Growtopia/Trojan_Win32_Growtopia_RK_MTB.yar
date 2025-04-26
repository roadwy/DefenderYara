
rule Trojan_Win32_Growtopia_RK_MTB{
	meta:
		description = "Trojan:Win32/Growtopia.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 85 c4 fe ff ff 30 84 0d c5 fe ff ff 41 83 f9 24 72 ed } //5
		$a_01_1 = {2e 67 72 6f 77 74 6f 70 69 61 32 2e 63 6f 6d 20 3d 20 25 73 } //1 .growtopia2.com = %s
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}