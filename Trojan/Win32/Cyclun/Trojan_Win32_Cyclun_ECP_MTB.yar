
rule Trojan_Win32_Cyclun_ECP_MTB{
	meta:
		description = "Trojan:Win32/Cyclun.ECP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {b9 f7 68 00 00 99 f7 f9 6a 00 80 c2 02 30 96 } //5
		$a_01_1 = {8d 4b 01 f7 e6 33 db 46 c1 ea 02 8d 04 92 3b f8 0f 45 d9 81 fe } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}