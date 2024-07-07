
rule Trojan_Win32_Dridex_GBC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 89 25 00 00 00 00 33 c0 3d 12 35 01 00 73 07 cc cc 40 cc cc eb f2 58 64 a3 00 00 00 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}