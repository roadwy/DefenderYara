
rule Trojan_Win32_Bayrob_MB_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.MB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 33 f6 39 75 08 0f 95 c0 3b c6 75 20 e8 78 11 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}