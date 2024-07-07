
rule Trojan_Win32_Zonsterarch_Y{
	meta:
		description = "Trojan:Win32/Zonsterarch.Y,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d2 89 55 e8 eb 2d 8b 45 e8 f7 d0 89 45 e8 8b 0d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}