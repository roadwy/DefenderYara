
rule Trojan_Win32_Zusy_SYU_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SYU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 8d 20 fe ff ff 83 c1 01 89 8d 20 fe ff ff 81 bd 20 fe ff ff 30 75 00 00 7d 65 e8 80 00 00 00 99 b9 fe 00 00 00 f7 f9 52 e8 72 00 00 00 99 b9 fe 00 00 00 f7 f9 52 8b 95 24 fe ff ff 52 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}