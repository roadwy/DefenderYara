
rule Trojan_Win32_Guloader_RPV_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 1c 08 d9 fd 0f ae e8 eb 2d } //1
		$a_01_1 = {39 c6 66 0f fd c7 d9 fd eb 35 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}