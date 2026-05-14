
rule Trojan_Win32_RootkitRevealer_SJ_MTB{
	meta:
		description = "Trojan:Win32/RootkitRevealer.SJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 14 6a 5c 89 04 8e 8b 54 24 18 8b 04 96 50 e8 c3 2d 00 00 66 89 68 02 8b 44 24 1c 83 c4 0c 40 89 44 24 10 8d 84 24 38 04 00 00 50 68 04 01 00 00 ff 15 30 91 cf 00 8d 8c 24 38 04 00 00 68 90 dd cf 00 8d 54 24 18 } //1
		$a_01_1 = {8b 4c 24 14 6a 5c 89 04 8e 8b 54 24 18 8b 04 96 50 e8 c3 2d 00 00 66 89 68 02 8b 44 24 1c 83 c4 0c 40 89 44 24 10 8d 84 24 38 04 00 00 50 68 04 01 00 00 ff 15 30 91 b8 00 8d 8c 24 38 04 00 00 68 90 dd b8 00 8d 54 24 18 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}