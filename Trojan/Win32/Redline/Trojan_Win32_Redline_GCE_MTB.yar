
rule Trojan_Win32_Redline_GCE_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 11 88 55 d3 0f be 45 d3 0f be 4d d3 8b 55 d4 83 e2 2b 8b 75 08 0f be 14 16 33 ca 81 f1 ?? ?? ?? ?? 03 c1 8b 4d 0c 03 4d d4 88 01 0f be 55 d3 8b 45 0c 03 45 d4 0f b6 08 2b ca 8b 55 0c 03 55 d4 88 0a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}