
rule Trojan_Win32_Graftor_SX_MTB{
	meta:
		description = "Trojan:Win32/Graftor.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 36 8d 85 f8 fe ff ff 50 ff 15 ?? ?? ?? ?? 59 85 c0 59 74 1b 47 83 c6 04 3b 7d 0c 7c e2 } //3
		$a_01_1 = {b9 81 00 00 00 33 c0 8d bd ee fa ff ff f3 ab 80 a5 f8 fd ff ff 00 6a 40 66 ab 59 33 c0 8d bd f9 fd ff ff 68 e0 40 40 00 f3 ab 66 ab aa } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}