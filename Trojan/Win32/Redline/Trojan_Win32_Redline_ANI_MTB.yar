
rule Trojan_Win32_Redline_ANI_MTB{
	meta:
		description = "Trojan:Win32/Redline.ANI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d2 88 55 a3 0f b6 45 a3 35 8d 00 00 00 88 45 a3 0f b6 4d a3 83 e9 58 88 4d a3 0f b6 55 a3 33 55 a4 88 55 a3 0f b6 45 a3 05 a7 00 00 00 88 45 a3 0f b6 4d a3 33 4d a4 88 4d a3 0f b6 55 a3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}