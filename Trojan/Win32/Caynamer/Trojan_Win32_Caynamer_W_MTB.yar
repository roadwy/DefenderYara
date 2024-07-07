
rule Trojan_Win32_Caynamer_W_MTB{
	meta:
		description = "Trojan:Win32/Caynamer.W!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 0c 33 45 10 8b 4d 08 89 01 5d c2 0c } //10
		$a_01_1 = {8b 45 f4 8b 4d c8 d3 e0 89 45 e4 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}