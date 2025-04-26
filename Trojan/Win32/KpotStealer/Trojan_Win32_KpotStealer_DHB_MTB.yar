
rule Trojan_Win32_KpotStealer_DHB_MTB{
	meta:
		description = "Trojan:Win32/KpotStealer.DHB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 f7 75 0c 8b 45 08 0f b6 0c 10 8b 55 10 03 55 fc 0f b6 02 33 c1 8b 4d 10 03 4d fc 88 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}