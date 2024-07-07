
rule Trojan_Win32_Redline_GCL_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c2 0f b6 45 aa c1 e0 07 09 d0 88 45 aa 80 45 aa 0e f6 55 aa 80 45 aa 61 8b 45 f4 30 45 aa f6 5d aa 80 6d aa 3c f6 5d aa 8b 45 f4 00 45 aa f6 55 aa 8b 45 f4 30 45 aa 8b 45 f4 00 45 aa 8d 55 9b 8b 45 f4 01 c2 0f b6 45 aa 88 02 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}